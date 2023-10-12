import logging
import asyncio
from pickle import dumps, loads
from honeybadgermpc.betterpairing import ZR, G1
#from pypairing import ZR, G1
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.broadcast.avid import AVID
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
from honeybadgermpc.share_recovery import poly_lagrange_at_x, poly_interpolate_at_x, interpolate_g1_at_x
import time, random
from honeybadgermpc.hbacss import Hbacss0
import pickle
from honeybadgermpc.utils.misc import flatten_lists
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


class Random_share(Hbacss0):
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg, index):
        all_shares_valid = True
        commitments, ephemeral_public_key, flag, dealer_id = loads(rbc_msg)
        shared_key = pow(ephemeral_public_key, self.private_key)
        self.tagvars[tag]['shared_key'][index] = shared_key
        self.tagvars[tag]['commitments'][index] = commitments
        self.tagvars[tag]['ephemeral_public_key'][index] = ephemeral_public_key

        try:
            if not flag:
                shares, auxes, witnesses, aux_info = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
                self.tagvars[tag]['witnesses'][index] = witnesses
            else:
                shares, auxes, witnesses = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
                self.tagvars[tag]['witnesses'][index] = witnesses
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False

        # self.tagvars[tag]['witnesses'] = witnesses

        # witnesses_zero = [(a_com, a_witness), (b_com, b_witness), witness_zero_c, t, t_proof]

        # call if decryption was successful

        if all_shares_valid:
            if self.poly_commit.batch_verify_eval(
                    commitments, self.my_id + 1, shares, auxes, witnesses
            ):
                self.tagvars[tag]['shares'][index] = shares
                self.tagvars[tag]['auxes'][index] = auxes
            else:
                all_shares_valid = False


        return all_shares_valid
    
    def _handle_dealer_msgs_batch(self, tag, dispersal_msg, rbc_msg, index):
        all_shares_valid = True
        commitments = [None] * self.n
        ephemeral_public_key = [None] * self.n
        dealer_id = [None] * self.n
        flag = [None] * self.n
        shared_key = [None] * self.n
        for i in index:
            commitments[i], ephemeral_public_key[i], flag[i], dealer_id[i] = loads(rbc_msg[i])
            shared_key[i] = pow(ephemeral_public_key[i], self.private_key)
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commitments
        self.tagvars[tag]['ephemeral_public_key'] = ephemeral_public_key

        shares = [None] * self.n
        auxes = [None] * self.n
        witnesses = [None] * self.n
        try:
            if not flag[0]:
                shares, auxes, witnesses = SymmetricCrypto.decrypt(str(shared_key[i]).encode(), dispersal_msg[i])
            else:
                for i in index:
                    shares[i], auxes[i], witnesses[i] = SymmetricCrypto.decrypt(str(shared_key[i]).encode(), dispersal_msg[i])
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False

        self.tagvars[tag]['witnesses'] = witnesses
        
        # call if decryption was successful
        self.tagvars[tag]['shares'] = {}
        self.tagvars[tag]['auxes'] = {}

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
                print("verify one by one", i)
                for i in range(self.n):
                    if self.poly_commit.batch_verify_eval(commitments[i], self.my_id + 1, shares[i], auxes[i], witnesses[i]):
                        self.tagvars[tag]['shares'][i] = shares[i]
                        self.tagvars[tag]['auxes'][i] = auxes[i]
                    else:
                        self.tagvars[tag]['implication_index'] = i
                all_shares_valid = False


        return all_shares_valid

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
            if len(acs_input) >= self.t + 1:
                break
            # if self._handle_dealer_msgs(tag, dispersal_msg[j], rbc_msg[j], j):
            #     flag_set[j] = True
            #     acs_input.add(j)
            # if len(acs_input) >= self.t + 1:
            #     break


        # perform ACS agreement with input ACS_input
        # leader = random.randint(0, self.n)
        async def common_subset():
            tag = f"common_subset"
            send, recv = self.get_send(tag), self.subscribe_recv(tag)
            leader = 2
            common_set = await optimal_common_set(0, self.my_id, avss_id, self.n, self.t, leader, acs_input, self.pk_bls, self.sk_bls, recv, send, _setup_rbc, avid_task,
                           self._handle_dealer_msgs, rbc_msg, dispersal_msg)
            return common_set
        #Agreement_set = [0, 3]
        # for j in range(self.n):
        if self._handle_dealer_msgs_batch(tag, dispersal_msg, rbc_msg, acs_input):
            common_set = await common_subset()
            self.tagvars[tag]['all_shares_valid'] = True
        # for i in common_set:
        #     if not flag_set[i]:
        #         self.tagvars[tag]['all_shares_valid'] = False
        
        print("handle")

        def random_shares_compute(common_set):
            def gen_vm_matrix(set):
                dim = len(set)
                vm_mat = [None] * dim
                for i in range(0, dim):
                    temp = [None] *dim
                    beta = ZR.hash(pickle.dumps(self.public_keys[set[i]]))
                    for j in range(0, dim):
                        temp[j] = beta ** j
                    vm_mat[i] = temp
                return vm_mat

            vm_matrix = gen_vm_matrix(common_set)

            def mat_mul(A, B):
                dim_row = len(A)
                dim_col = len(B[0])
                res = [[ZR(0) for i in range(dim_col)] for j in range(dim_row)]
                for i in range(dim_row):
                    for j in range(dim_col):
                        for k in range(dim_row):
                            res[i][j] += A[i][k] * B[common_set[k]][j]
                return flatten_lists(res)

            def dot_pow(B_in_zp, A_in_G1):
                dim_row = len(B_in_zp)
                dim_col = len(A_in_G1[0])
                res = [[G1.identity() for i in range(dim_col)] for j in range(dim_row)]
                for i in range(dim_row):
                    for j in range(dim_col):
                        for k in range(dim_row):
                            res[i][j] *= A_in_G1[common_set[k]][j] ** B_in_zp[i][k]
                return flatten_lists(res)

            random_shares = mat_mul(vm_matrix, self.tagvars[tag]['shares'])
            random_auxes = mat_mul(vm_matrix, self.tagvars[tag]['auxes'])
            random_coms = dot_pow(vm_matrix, self.tagvars[tag]['commitments'])
            random_wits = dot_pow(vm_matrix, self.tagvars[tag]['witnesses'])
            return random_coms, random_shares, random_auxes, random_wits

            # assert self.poly_commit.batch_verify_eval(random_coms, self.my_id + 1, random_shares, random_auxes, random_wits)

        coms, shares, auxes, witnesses = random_shares_compute(list(common_set))

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
                    self.output_queue.put_nowait((coms, shares, auxes, witnesses))
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
        print("avss finished")
        await self._process_avss_msg(avss_id, client, dealer_id, broadcast_msg, avid_task)

