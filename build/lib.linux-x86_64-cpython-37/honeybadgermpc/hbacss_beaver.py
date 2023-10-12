import logging
import asyncio
import pypairing
from pickle import dumps, loads
#from honeybadgermpc.betterpairing import ZR, G1
from honeybadgermpc.betterpairing import ZR, G1
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.broadcast.avid import AVID
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
from honeybadgermpc.share_recovery import poly_lagrange_at_x, poly_interpolate_at_x, interpolate_g1_at_x
import time
from honeybadgermpc.hbacss import Hbacss1
from honeybadgermpc.hbacss_random_share import Random_share
import pickle
from honeybadgermpc.utils.misc import flatten_lists
from functools import reduce
import operator
from honeybadgermpc.optimal_common_set import optimal_common_set


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)


class HbAVSSMessageType:
    OK = "OK"
    IMPLICATE = "IMPLICATE"
    READY = "READY"
    RECOVERY = "RECOVERY"
    RECOVERY1 = "RECOVERY1"
    RECOVERY2 = "RECOVERY2"
    KDIBROADCAST = "KDIBROADCAST"


def get_avss_params(n, t):
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random(0)
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


class Beaver(Hbacss1):
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg, index):
        all_shares_valid = True
        commitments = [None] * self.n
        ephemeral_public_key = [None] * self.n
        dealer_id = [None] * self.n
        flag = [None] * self.n
        shared_key = [None] * self.n
        aux_info = [None] * self.n

        for i in index:
            commitments[i], ephemeral_public_key[i], flag[i], dealer_id[i] = loads(rbc_msg[i])
            shared_key[i] = pow(ephemeral_public_key[i], self.private_key)
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commitments
        self.tagvars[tag]['ephemeral_public_key'] = ephemeral_public_key

        shares = [None] * self.n
        auxes = [None] * self.n
        witnesses = [None] * self.n
        aux_info = [None] *  self.n

        try:
            if not flag[0]:
                for i in index:
                    shares[i], auxes[i], witnesses[i], aux_info[i] = SymmetricCrypto.decrypt(str(shared_key[i]).encode(), dispersal_msg[i])
                self.tagvars[tag]['witnesses'] = witnesses
            else:
                shares, auxes, witnesses = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
                self.tagvars[tag]['witnesses'][index] = witnesses
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False

        # witnesses_zero = [(a_com, a_witness), (b_com, b_witness), witness_zero_c, t, t_proof]

        # call if decryption was successful

        commitprod = G1.identity()
        witnessprod = G1.identity()
        sharesum = ZR(0)
        auxsum = ZR(0)
        for j in index:
            for k in range(len(commitments[j])):
                commitprod *= commitments[j][k]
                witnessprod *= witnesses[j][k]
                sharesum += shares[j][k]
                auxsum += auxes[j][k]

        if all_shares_valid:
            if self.poly_commit.verify_eval(
                    commitprod, self.my_id + 1, sharesum, auxsum, witnessprod
            ):
                self.tagvars[tag]['shares'] = shares
                self.tagvars[tag]['auxes'] = auxes
            else:
                all_shares_valid = False
        # verify
        def verify(dealer_id, aux_info, pc):
            t = aux_info[3]
            t_proof = aux_info[4]

            a_com = aux_info[0][0]
            a_share_auxes = [t[i][0] for i in range(len(a_com))]
            a_wit = aux_info[0][1]
            assert pc.batch_verify_eval_zero_knowledge(a_com, dealer_id + 1, a_share_auxes, a_wit)

            b_com = aux_info[1][0]
            b_share_auxes = [t[i][1] for i in range(len(a_com))]
            b_wit = aux_info[1][1]
            assert pc.batch_verify_eval_zero_knowledge(b_com, dealer_id + 1, b_share_auxes, b_wit)

            c_wit_zero = aux_info[2]
            c_share_auxes = [t[i][2] for i in range(len(a_com))]
            assert pc.batch_verify_eval_zero_knowledge(commitments[dealer_id], 0, c_share_auxes, c_wit_zero)


            for i in range(len(t)):
                assert pc.verify_product(t[i], t_proof[i])

            return True

        if all_shares_valid:
            for i in index:
                verify(dealer_id[i], aux_info[i], self.poly_commit)
            return True

    async def _process_avss_msg(self, avss_id, client, dealer_id, broadcast_msg, avid_task):
        # tag = f"{dealer_id}-{avss_id}-B-AVSS"
        tag = f"{avss_id}-B-AVID"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self.tagvars[tag] = {}
        self._init_recovery_vars(tag)

        self.tagvars[tag]['shared_key'] = {}
        self.tagvars[tag]['commitments'] = {}
        self.tagvars[tag]['ephemeral_public_key'] = {}
        self.tagvars[tag]['witnesses'] = {}
        self.tagvars[tag]['shares'] = {}
        self.tagvars[tag]['auxes'] = {}

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['avid'] = avid_task
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False

        async def _setup_rbc(j):
            """Setup the sub protocols RBC, BA and common coin.
            :param int j: Node index for which the setup is being done.
            """
            tag = f"{avss_id}-{j}-B-RBC"
            send, recv = self.get_send(tag), self.subscribe_recv(tag)

            # Only leader gets input
            rbc_input = broadcast_msg if j == self.my_id else None
            rbc_msg = await reliablebroadcast(
                tag,
                self.my_id,
                self.n,
                self.t,
                j,
                rbc_input,
                recv,
                send,
                client_mode = False,
            )  # (# noqa: E501)

            return rbc_msg

        rbc_msg = [None] * self.n
        dispersal_msg = [None] * self.n

        acs_input = set()
        flag_set = {}
        for j in range(self.n):
            rbc_msg[j] = await _setup_rbc(j)
            dispersal_msg[j] = await avid_task[j].retrieve(f"{avss_id}-{j}-B-AVID", self.my_id)   
            acs_input.add(j)
            if len(acs_input) >= 2 * self.t + 1:
                break

        # perform ACS agreement with input ACS_input
        # leader = random.randint(0, self.n)
        async def common_subset():
            tag = f"common_subset"
            send, recv = self.get_send(tag), self.subscribe_recv(tag)
            leader = 2
            common_set = await optimal_common_set(0, self.my_id, avss_id, self.n, self.t, leader, acs_input,
                                                  self.pk_bls, self.sk_bls, recv, send, _setup_rbc, avid_task,
                                                  self._handle_dealer_msgs, rbc_msg, dispersal_msg, flag_set)
            return common_set

        # Agreement_set = [0, 3]
        # for j in range(self.n):

        if self._handle_dealer_msgs(tag, dispersal_msg, rbc_msg, acs_input):
            common_set = await common_subset()

        # for i in common_set:
        #     if i not in ACS_input:
        #         rbc_msg[i] = await _setup_rbc(i)
        #         dispersal_msg[i] = await avid_task[i].retrieve(f"{avss_id}-{i}-B-AVID", self.my_id)
        #         if self._handle_dealer_msgs(tag, dispersal_msg[i], rbc_msg[i], i):
        #             flag_set[i] = True

        self.tagvars[tag]['all_shares_valid'] = True

        def beaver_triples_Gen(agreement_set):
            def lagrange_coefficient(xs, x_recomb=ZR(0)):
                vector = []
                for i, x_i in enumerate(xs):
                    factors = [
                        (x_recomb - x_k) / (x_i - x_k) for k, x_k in enumerate(xs) if k != i
                    ]
                    vector.append(reduce(operator.mul, factors))
                return vector

            lagrange_coe = lagrange_coefficient([item + 1 for item in agreement_set])

            def degree_reduction(shares, operate1, operate2):
                fliped_shares = list(map(list, zip(*shares)))
                t_shares = [None] * len(fliped_shares)
                i = 0
                for item in fliped_shares:
                    t_shares[i] = reduce(operate2, map(operate1, item, lagrange_coe))
                    i += 1
                return t_shares

            shares_in_agreement_set = [None] * len(agreement_set)
            # auxes_in_agreement_set = [None] * len(agreement_set)
            # coms_in_agreement_set = [None] * len(agreement_set)
            # wits_in_agreement_set = [None] * len(agreement_set)
            for i in range(len(agreement_set)):
                shares_in_agreement_set[i] = self.tagvars[tag]['shares'][agreement_set[i]]
                # auxes_in_agreement_set[i] = self.tagvars[tag]['auxes'][agreement_set[i]]
                # coms_in_agreement_set[i] = self.tagvars[tag]['commitments'][agreement_set[i]]
                # wits_in_agreement_set[i] = self.tagvars[tag]['witnesses'][agreement_set[i]]


            shares = degree_reduction(shares_in_agreement_set, operator.mul, operator.add)
            # auxes = degree_reduction(auxes_in_agreement_set, operator.mul, operator.add)
            # coms = degree_reduction(coms_in_agreement_set, operator.pow, operator.mul)
            # wits = degree_reduction(wits_in_agreement_set, operator.pow, operator.mul)
            # return coms, shares, auxes, wits
            return shares


            #assert self.poly_commit.batch_verify_eval(random_coms, self.my_id + 1, random_shares, random_auxes, random_wits)

        # coms, shares, auxes, witnesses = beaver_triples_Gen(list(common_set))
        shares = beaver_triples_Gen(list(common_set))

        if self.tagvars[tag]['all_shares_valid']:
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            self.tagvars[tag]['in_share_recovery'] = True

        # obtain
        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    # todo: implicate should be forwarded to others if we haven't sent one
                    # implication_type, implication_index = await self._handle_implication(tag, sender, avss_msg[1])
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            # todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1,
                               HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[
                0] == HbAVSSMessageType.OK and sender not in ok_set:  # and self.tagvars[tag]['all_shares_valid']:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)
                if len(ok_set) >= (2 * self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # READY
            if avss_msg[0] == HbAVSSMessageType.READY and (sender not in ready_set):
                # logger.debug("[%d] Received READY from [%d]", self.my_id, sender)
                ready_set.add(sender)
                if len(ready_set) >= (self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # if 2t+1 ready -> output shares
            if len(ready_set) >= (2 * self.t + 1):
                # output result by setting the future value
                if self.tagvars[tag]['all_shares_valid'] and not output:
                    # self.output_queue.put_nowait((coms, shares, auxes, witnesses))
                    self.output_queue.put_nowait((shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                self.tagvars[tag] = {}
                break

    async def avss(self, avss_id, client, values=None, dealer_id=None, client_mode=False):
        """
        A batched version of avss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        if client_mode:
            assert dealer_id is not None
            assert dealer_id == self.n
        assert type(avss_id) is int

        logger.debug(
            "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
            self.my_id,
            avss_id,
            dealer_id,
            client_mode,
        )

        # In the client_mode, the dealer is the last node
        n = self.n if not client_mode else self.n + 1
        broadcast_msg = None
        dispersal_msg_list = None
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(values, n)

        def _setup_avid(j):
            """Setup the sub protocols avid.
            :param int j: Node index for which the setup is being done.
            """
            tag = f"{avss_id}-{j}-B-AVID"
            send, recv = self.get_send(tag), self.subscribe_recv(tag)
            avid = AVID(n, self.t, j, recv, send, n)

            #  start disperse in the background
            #await avid.disperse(tag, self.my_id, dispersal_msg_list)
            self.avid_msg_queue.put_nowait((avid, tag, dispersal_msg_list))

            # retrieve the z
            #return await avid.retrieve(tag, self.my_id)
            return avid


        #dispersal_msg = [None] * n
        avid_task = [None] * n
        for j in range(self.n):
            avid_task[j] = _setup_avid(j)

        # avss processing
        await self._process_avss_msg(avss_id, client, dealer_id, broadcast_msg, avid_task)

