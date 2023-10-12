import logging
import asyncio
import pypairing
from pickle import dumps, loads
from honeybadgermpc.betterpairing import ZR, G1
# from pypairing import ZR, G1
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.broadcast.avid import AVID
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
from honeybadgermpc.share_recovery import poly_lagrange_at_x, poly_interpolate_at_x, interpolate_g1_at_x
import time
from honeybadgermpc.poly_commit_const import PolyCommitConst, gen_pc_const_crs


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
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


class Hbacss0:
    #@profile
    def __init__(
            self, public_keys, private_key, pk_bls, sk_bls, crs, n, t, my_id, send, recv, pc=None, field=ZR
    ):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.my_id = n, t, my_id
        #todo: g should be baked into the pki or something
        if type(crs[0]) is G1:
            self.g = crs[0]
        else:
            self.g = crs[0][0]

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.pk_bls = pk_bls
        self.sk_bls = sk_bls

        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        if pc is not None:
            self.poly_commit = pc
        else:
            self.poly_commit = PolyCommitConst(crs)
            # self.poly_commit = PolyCommitLog(crs=None, degree_max=t)
            # self.poly_commit.preprocess_prover()
            # self.poly_commit.preprocess_verifier()
        self.avid_msg_queue = asyncio.Queue()
        self.tasks = []
        self.shares_future = asyncio.Future()
        self.output_queue = asyncio.Queue()
        self.tagvars = {}

    async def _recv_loop(self, q):
        while True:
            avid, tag, dispersal_msg_list = await q.get()
            self.tasks.append(
                asyncio.create_task(avid.disperse(tag, self.my_id, dispersal_msg_list))
            )

    def __enter__(self):
        self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        return self

    def __exit__(self, typ, value, traceback):
        self.subscribe_recv_task.cancel()
        self.avid_recv_task.cancel()
        for task in self.tasks:
            task.cancel()
    #@profile
    async def _handle_implication(self, tag, j, j_sk):

        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments =  self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = [None] * self.n
        j_shared_key = [None] * self.n
        for i in range(self.n):
            implicate_msg[i] = await self.tagvars[tag]['avid'][i].retrieve(tag, j)
            j_shared_key[i] = pow(self.tagvars[tag]['ephemeral_public_key'][i], j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        j_shares = [None] * self.n
        j_auxes = [None] * self.n
        j_witnesses = [None] * self.n


        try:
            for i in range(self.n):
                j_shares[i], j_auxes[i], j_witnesses[i] = SymmetricCrypto.decrypt(str(j_shared_key[i]).encode(), implicate_msg[i])
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True

        flag = False
        for i in range(self.n):
            if not self.poly_commit.batch_verify_eval(commitments[i], j + 1, j_shares[i], j_auxes[i], j_witnesses[i]):
                self.tagvars[tag]['implication_index'] = i
                flag = True

        return flag

        # return not self.poly_commit.batch_verify_eval_all(
        #     commitments, j + 1, j_shares, j_auxes, j_witnesses
        # )



    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False
    #@profile
    async def _process_avss_msg(self, avss_id, client, dealer_id, rbc_msg, avid_task):
        #tag = f"{dealer_id}-{avss_id}-B-AVSS"
        tag = f"{avss_id}-B-AVID"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self.tagvars[tag] = {}
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['avid'] = avid_task
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False

        #retrieve the z
        dispersal_msg = [None] * self.n
        for i in range(self.n):
            dispersal_msg[i] = await avid_task[i].retrieve(f"{avss_id}-{i}-B-AVID", self.my_id)

        # this function will both load information into the local variable store 
        # and verify share correctness
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dispersal_msg, rbc_msg)

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
                    #todo: implicate should be forwarded to others if we haven't sent one
                    #implication_type, implication_index = await self._handle_implication(tag, sender, avss_msg[1])
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:# and self.tagvars[tag]['all_shares_valid']:
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
                    shares = self.tagvars[tag]['shares']
                    int_shares = [[int(shares[i][j]) for j in range(len(shares[0]))] for i in range(len(shares))]
                    shares_zp = {'dealer_id':dealer_id, 'client':client, 'com':self.tagvars[tag]['commitments'], 'shares':shares, 'auxes':self.tagvars[tag]['auxes'], 'wit': self.tagvars[tag]['witnesses']}
                    #shares_zp =[self.tagvars[tag]['commitments'], shares, self.tagvars[tag]['auxes'], self.tagvars[tag]['witnesses']]
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares, shares_zp))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                self.tagvars[tag] = {}
                break

    #@profile
    def _get_dealer_msg(self, values_dealer, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        flag = True
        if type(values_dealer) == tuple:
            values = values_dealer[0]
            a_info = values_dealer[1]
            b_info = values_dealer[2]
            flag = False
        else:
            values = values_dealer
        secret_count = len(values)

        phi = [None] * secret_count
        phi_hat = [None] * secret_count
        commitments = [None] * secret_count
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        #r = ZR.random()
        for k in range(secret_count):
            phi[k] = self.poly.random(self.t, values[k])
            commitments[k], phi_hat[k] = self.poly_commit.commit(phi[k])

        ephemeral_secret_key = self.field.random()
        ephemeral_public_key = pow(self.g, ephemeral_secret_key)
        dispersal_msg_list = [None] * n
        witnesses = self.poly_commit.double_batch_create_witness(phi, phi_hat)

        if not flag:
            t = [None] * secret_count
            t_proof = [None] * secret_count
            for i in range (secret_count):
                t[i], t_proof[i] = self.poly_commit.prove_product(a_info[2][i], a_info[3][i], b_info[2][i], b_info[3][i], phi[i](0), phi_hat[i](0))
            witness_zero_c, com_zero = self.poly_commit.zero_witness(phi, phi_hat)
            aux_info = [(a_info[0], a_info[1]), (b_info[0], b_info[1]), witness_zero_c, t, t_proof]
        #def product_prove(T_a, T_b, T_c)

        for i in range(n):
            shared_key = pow(self.public_keys[i], ephemeral_secret_key)
            phis_i = [phi[k](i + 1) for k in range(secret_count)]
            phi_hats_i = [phi_hat[k](i + 1) for k in range(secret_count)]
            if not flag:
                z = (phis_i, phi_hats_i, witnesses[i + 1], aux_info)
            else:
                z = (phis_i, phi_hats_i, witnesses[i + 1])
            zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
            dispersal_msg_list[i] = zz
        return dumps((commitments, ephemeral_public_key, flag, self.my_id)), dispersal_msg_list

    #@profile
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg):
        all_shares_valid = True
        commitments = [None] * self.n
        ephemeral_public_key = [None] * self.n
        flag = [None] * self.n
        dealer_id = [None] * self.n
        shared_key = [None] * self.n
        for i in range(self.n):
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
                shares, auxes, witnesses, aux_info = SymmetricCrypto.decrypt(str(shared_key[i]).encode(), dispersal_msg[i])
            else:
                for i in range(self.n):
                    shares[i], auxes[i], witnesses[i] = SymmetricCrypto.decrypt(str(shared_key[i]).encode(), dispersal_msg[i])
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False

        self.tagvars[tag]['witnesses'] = witnesses

        #witnesses_zero = [(a_com, a_witness), (b_com, b_witness), witness_zero_c, t, t_proof]
        
        # call if decryption was successful
        self.tagvars[tag]['shares'] = {}
        self.tagvars[tag]['auxes'] = {}

        if all_shares_valid:
            if self.poly_commit.batch_verify_eval_all(
                    commitments, self.my_id + 1, shares, auxes, witnesses
            ):
                self.tagvars[tag]['shares'] = shares
                self.tagvars[tag]['auxes'] = auxes
            else:
                for i in range(self.n):
                    if self.poly_commit.batch_verify_eval(commitments[i], self.my_id + 1, shares[i], auxes[i], witnesses[i]):
                        self.tagvars[tag]['shares'][i] = shares[i]
                        self.tagvars[tag]['auxes'][i] = auxes[i]
                    else:
                        self.tagvars[tag]['implication_index'] = i
                all_shares_valid = False

        # verify
        def verify(aux_info, pc):
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



            for i in range(len(t)):
                assert pc.verify_product(t[i], t_proof[i])

            return True

        if all_shares_valid and not flag:
            verify(aux_info, self.poly_commit)
        return all_shares_valid

    #@profile
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
                n,
                self.t,
                j,
                rbc_input,
                recv,
                send,
                client_mode=client_mode,
            )  # (# noqa: E501)

            return rbc_msg

        rbc_msg = [None] * n
        for j in range(self.n):
            rbc_msg[j] = await _setup_rbc(j)


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
        await self._process_avss_msg(avss_id, client, dealer_id, rbc_msg, avid_task)

class Hbacss1(Hbacss0):
    def _init_recovery_vars(self, tag):
        self.tagvars[tag]['finished_interpolating_commits'] = False
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        if not self.tagvars[tag]['in_share_recovery']:
            return

        try:
            implication_index = self.tagvars[tag]['implication_index']
        except Exception as e:  # TODO: Add specific exception
            logger.debug("No implication_index:", e)


        ls = len(self.tagvars[tag]['commitments'][implication_index]) // (self.t + 1)
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['finished_interpolating_commits']:
            all_commits = [ [] for l in range(ls)]
            for l in range(ls):
                known_commits = self.tagvars[tag]['commitments'][implication_index][l * (self.t + 1): (1 + l) * (self.t + 1)]
                known_commit_coords = [[i + 1, known_commits[i]] for i in range(self.t + 1)]
                # line 502
                interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in range(self.t + 1, self.n)]
                #interpolated_commits = known_commits + known_commits + known_commits
                all_commits[l] = known_commits + interpolated_commits
            self.tagvars[tag]['all_commits'] = all_commits
            self.tagvars[tag]['finished_interpolating_commits'] = True

            #init some variables we'll need later
            self.tagvars[tag]['r1_coords_l'] = [ [] for l in range(ls)]
            self.tagvars[tag]['r2_coords_l'] = [ [] for l in range(ls)]
            self.tagvars[tag]['r1_aux_coords_l'] = [[] for l in range(ls)]
            self.tagvars[tag]['r2_aux_coords_l'] = [[] for l in range(ls)]
            self.tagvars[tag]['sent_r2'] = False
            self.tagvars[tag]['r1_set'] = set()
            self.tagvars[tag]['r2_set'] = set()
            
            if self.tagvars[tag]['all_shares_valid']:
                logger.debug("[%d] prev sent r1", self.my_id)
                all_evalproofs = [ [] for l in range(ls)]
                all_points = [ [] for l in range(ls)]
                all_aux_points = [[] for l in range(ls)]
                for l in range(ls):
                    # the proofs for the specific shares held by this node
                    known_evalproofs = self.tagvars[tag]['witnesses'][implication_index][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_evalproof_coords = [[i + 1, known_evalproofs[i]] for i in range(self.t + 1)]
                    # line 504
                    interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
                                            range(self.t + 1, self.n)]
                    #interpolated_evalproofs = known_evalproofs + known_evalproofs + known_evalproofs
                    all_evalproofs[l] = known_evalproofs + interpolated_evalproofs
    
                    # another way of doing the bivariate polynomial. Essentially the same as how commits are interpolated
                    known_points = self.tagvars[tag]['shares'][implication_index][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_point_coords = [[i + 1, known_points[i]] for i in range(self.t + 1)]
                    mypoly = self.poly.interpolate(known_point_coords)
                    interpolated_points = [mypoly(i+1) for i in range(self.t + 1, self.n)]
                    all_points[l] = known_points + interpolated_points

                    #auxes
                    known_auxes = self.tagvars[tag]['auxes'][implication_index][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_aux_coords = [[i + 1, known_auxes[i]] for i in range(self.t + 1)]
                    my_aux_poly = self.poly.interpolate(known_aux_coords)
                    interpolated_aux_points = [my_aux_poly(i + 1) for i in range(self.t + 1, self.n)]
                    all_aux_points[l] = known_auxes + interpolated_aux_points

                logger.debug("[%d] in between r1", self.my_id)
                # lines 505-506
                for j in range(self.n):
                    send(j, (HbAVSSMessageType.RECOVERY1, [ all_points[l][j] for l in range(ls)] , [ all_aux_points[l][j] for l in range(ls)], [all_evalproofs[l][j] for l in range(ls)]))
                logger.debug("[%d] sent r1", self.my_id)



        if avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not self.tagvars[tag]['sent_r2']:
            logger.debug("[%d] prev sent r2", self.my_id)
            _, points, aux_points, proofs = avss_msg
            all_commits = self.tagvars[tag]['all_commits']
            if self.poly_commit.batch_verify_eval([all_commits[l][self.my_id] for l in range(ls)], sender + 1, points, aux_points, proofs):
                if sender not in self.tagvars[tag]['r1_set']:
                    self.tagvars[tag]['r1_set'].add(sender)
                    for l in range(ls):
                        self.tagvars[tag]['r1_coords_l'][l].append([sender, points[l]])
                        self.tagvars[tag]['r1_aux_coords_l'][l].append([sender, aux_points[l]])
                    #r1_coords.append([sender, point])
                if len(self.tagvars[tag]['r1_set']) == self.t + 1:
                    #r1_poly = self.poly.interpolate(r1_coords)
                    r1_poly_l = [ [] for l in range(ls)]
                    r1_aux_poly_l = [[] for l in range(ls)]
                    for l in range(ls):
                        r1_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_coords_l'][l])
                        r1_aux_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_aux_coords_l'][l])
                    for j in range(self.n):
                        r1_points_j = [r1_poly_l[l](j) for l in range(ls)]
                        r1_aux_points_j = [r1_aux_poly_l[l](j) for l in range(ls)]
                        #send(j, (HbAVSSMessageType.RECOVERY2, r1_poly(j)))
                        send(j, (HbAVSSMessageType.RECOVERY2, r1_points_j, r1_aux_points_j))
                    self.tagvars[tag]['sent_r2'] = True
                    logger.debug("[%d] sent r2", self.my_id)

        if avss_msg[0] == HbAVSSMessageType.RECOVERY2 and not self.tagvars[tag]['all_shares_valid']: # and self.tagvars[tag]['sent_r2']:
            _, points, aux_points = avss_msg
            if sender not in self.tagvars[tag]['r2_set']:
                self.tagvars[tag]['r2_set'].add(sender)
                #r2_coords.append([sender, point])
                for l in range(ls):
                    self.tagvars[tag]['r2_coords_l'][l].append([sender, points[l]])
                    self.tagvars[tag]['r2_aux_coords_l'][l].append([sender, aux_points[l]])
            if len(self.tagvars[tag]['r2_set']) == 2 * self.t + 1:
                # todo, replace with robust interpolate that takes at least 2t+1 values
                # this will still interpolate the correct degree t polynomial if all points are correct
                r2_poly_l = [ [] for l in range(ls)]
                r2_aux_poly_l = [[] for l in range(ls)]
                shares = []
                auxes = []
                for l in range(ls):
                    r2_poly = self.poly.interpolate(self.tagvars[tag]['r2_coords_l'][l])
                    shares += [r2_poly(i) for i in range(self.t + 1)]
                    r2_aux_poly = self.poly.interpolate(self.tagvars[tag]['r2_aux_coords_l'][l])
                    auxes += [r2_aux_poly(i) for i in range(self.t + 1)]
                multicast((HbAVSSMessageType.OK, ""))

                self.tagvars[tag]['all_shares_valid'] = True
                self.tagvars[tag]['shares'][implication_index] = shares
                self.tagvars[tag]['auxes'][implication_index] = auxes

