import logging
import asyncio
from pickle import dumps, loads
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.broadcast.avid import AVID
from honeybadgermpc.utils.misc import wrap_send, subscribe_recv
import time
from honeybadgermpc.optimal_common_set import optimal_common_set
from ctypes import *
import json


lib = CDLL("./gnark-crypto/kzg_ped_out.so")

lib.pyCommit.argtypes = [c_char_p, c_char_p, c_int]
lib.pyCommit.restype = c_char_p

lib.pyKeyEphemeralGen.argtypes = [c_char_p]
lib.pyKeyEphemeralGen.restype = c_char_p

lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyNewSRS.restype = c_bool

lib.pySharedKeysGen_sender.argtypes = [c_char_p, c_char_p, c_int]
lib.pySharedKeysGen_sender.restype = c_char_p

lib.pySharedKeysGen_recv.argtypes = [c_char_p, c_char_p]
lib.pySharedKeysGen_recv.restype = c_char_p

lib.pyBatchVerify_all.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyNewSRS.restype = c_bool

lib.pyRandomShareCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyRandomShareCompute.restype = c_char_p



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


class Random_share():
    
    #@profile
    def __init__(
            self, public_keys, private_key, pk_bls, sk_bls, srs, n, t, my_id, send, recv):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.my_id = n, t, my_id
        #todo: g should be baked into the pki or something
        self.srs_kzg = srs
        
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.pk_bls = pk_bls
        self.sk_bls = sk_bls
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
    def _get_dealer_msg(self, values_dealer, msgmode, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        if msgmode == "random_share":
            secret = values_dealer
        begin_time = time.time()      
        commitmentlistandprooflist = lib.pyCommit(self.srs_kzg, secret, self.t)
        end_time = time.time()
        print(f"time to commit: {(end_time - begin_time)}") 
        logger.info(f"time to commit: {(end_time - begin_time)}") 
        
        deserialized_commitmentlistandprooflist = json.loads(commitmentlistandprooflist.decode('utf-8'))
        commitments = deserialized_commitmentlistandprooflist["commitmentList"]
        
        # com = json.dumps(deserialized_commitmentlistandprooflist).encode('utf-8')
        # for i in range(self.n):
        #     print(i, "验证")
        #     proof = json.dumps(deserialized_commitmentlistandprooflist["batchproofsofallparties"][i]).encode('utf-8')
        #     print(i, "----------", lib.pyBatchVerify(self.srs_kzg,com, proof, i))
            

        proofandshares = []
        for i in range(self.n):
            proofandshares.append(deserialized_commitmentlistandprooflist["batchproofsofallparties"][i])
        
        serialized_ephemeralpublicsecretkey = lib.pyKeyEphemeralGen(self.srs_kzg, self.public_keys)
        deserialized_ephemeralpublicsecretsharedkey = json.loads(serialized_ephemeralpublicsecretkey.decode('utf-8'))
        
        serialized_ephemeralpublickey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralpublickey']).encode('utf-8')
        serialized_ephemeralsecretkey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralsecretkey']).encode('utf-8')
        
        dispersal_msg_list = [None] * n
        shared_keys = [None] * n

        for i in range(n):
            shared_keys[i] = lib.pySharedKeysGen_sender(self.public_keys, serialized_ephemeralsecretkey, i)
            dispersal_msg_list[i] = SymmetricCrypto.encrypt(str(shared_keys[i]).encode(), proofandshares[i])
        
        return dumps((commitments, serialized_ephemeralpublickey, self.my_id)), dispersal_msg_list
    
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg, index):
        all_shares_valid = True
        try:
            for i in index:
                commitments, serialized_ephemeralpublickey, dealer_id = loads(rbc_msg)
                serialized_sharedkey =  lib.pySharedKeysGen_recv(serialized_ephemeralpublickey[i], self.private_key)
                proofandshares = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
        
        serialized_commitment = json.dumps(commitments).encode('utf-8')
        serialized_proofandshares = json.dumps(proofandshares).encode('utf-8')

        if all_shares_valid:
            if lib.pyBatchVerify(self.srs_kzg, serialized_commitment, serialized_proofandshares, self.my_id) == int(1):
                self.tagvars[tag]['commitments'] = commitments
                self.tagvars[tag]['proofsandshares'] = proofandshares
            else:
                self.tagvars[tag]['implication_index'] = i
                all_shares_valid = False
        return all_shares_valid
    
    def _handle_dealer_msgs_batch(self, tag, dispersal_msg, rbc_msg, index):
        all_shares_valid = True
        commitments = [None] * self.n
        serialized_ephemeralpublickey = [None] * self.n
        dealer_id = [None] * self.n
        proofandshares = [None] * self.n
        
        try:
            for i in index:
                commitments[i], serialized_ephemeralpublickey[i], dealer_id[i] = loads(rbc_msg[i])
                serialized_sharedkey =  lib.pySharedKeysGen_recv(serialized_ephemeralpublickey[i], self.private_key)
                proofandshares[i] = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg[i])
                # checkresult = lib.pyBatchVerify(self.srs_kzg, commitments[i], proofandshares[i], self.my_id)
                # print("checkresult", i, checkresult)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
        
        filtered_commitments = [item for item in commitments if item is not None ]
        filtered_proofandshares = [item for item in proofandshares if item is not None ]
        serialized_commitment = json.dumps(filtered_commitments).encode('utf-8')
        serialized_proofandshares = json.dumps(filtered_proofandshares).encode('utf-8')
        
        begin_time = time.time()
        if all_shares_valid:
            if lib.pyBatchVerify_all(self.srs_kzg, serialized_commitment, serialized_proofandshares, self.my_id) == int(1):
                self.tagvars[tag]['commitments'] = serialized_commitment
                self.tagvars[tag]['proofsandshares'] = serialized_proofandshares 
            else:
                print("verify one by one", i)
                for i in index:
                    if lib.pyBatchVerify(self.srs_kzg, commitments[i], proofandshares[i], self.my_id) == int(1):
                        self.tagvars[tag]['commitments'] = commitments
                        self.tagvars[tag]['proofsandshares'] = proofandshares
                    else:
                        self.tagvars[tag]['implication_index'] = i
                all_shares_valid = False
        end_time = time.time()
        print(f"验证证据的时间: {(end_time - begin_time)}")
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
        self.tagvars[tag]['proofsandshares'] = {}

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
        # flag_set = {}
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
            common_set = await optimal_common_set(0, self.my_id, avss_id, self.n, self.t, leader, acs_input, self.pk_bls, self.sk_bls, recv, send, _setup_rbc, avid_task,
                           self._handle_dealer_msgs, rbc_msg, dispersal_msg)
            return common_set
        #Agreement_set = [0, 3]
        # for j in range(self.n):
        
        
        if self._handle_dealer_msgs_batch(tag, dispersal_msg, rbc_msg, acs_input):
            print("commonsubset_begin")
            common_set = await common_subset()
            self.tagvars[tag]['all_shares_valid'] = True
        
        begin_time = time.time()
        serialized_input = json.dumps(list(common_set)).encode('utf-8')
        serializedcoms_proofs = lib.pyRandomShareCompute(serialized_input, self.public_keys, self.tagvars[tag]['commitments'], self.tagvars[tag]['proofsandshares'], self.t)
        end_time = time.time()
        print(f"计算random share的时间: {(end_time - begin_time)}")
        
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
                    self.output_queue.put_nowait(serializedcoms_proofs)
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                self.tagvars[tag] = {}
                break

    async def avss(self, avss_id, client, msgmode, values=None, dealer_id=None, client_mode=False):
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
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(values, msgmode, n)

        
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

