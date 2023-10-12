from pytest import mark
from random import randint
from contextlib import ExitStack
from pickle import dumps
from honeybadgermpc.polynomial import polynomials_over, EvalPoint
from honeybadgermpc.poly_commit_const_dl import PolyCommitConstDL, gen_pc_const_dl_crs
# from honeybadgermpc.betterpairing import G1, ZR
from honeybadgermpc.hbavss_kzg import Hbacss0, Hbacss1, Hbacss2
from honeybadgermpc.mpc import TaskProgramRunner
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.utils.misc import print_exception_callback
from honeybadgermpc.field import GF
from honeybadgermpc.elliptic_curve import Subgroup
import asyncio
from honeybadgermpc.router import SimpleRouter, TestRouter
from honeybadgermpc.router import Router
from honeybadgermpc.reed_solomon import EncoderFactory, DecoderFactory
#from fixtures import test_router

from honeybadgermpc.poly_commit_const import PolyCommitConst, gen_pc_const_crs

from honeybadgermpc.utils.misc import (
    wrap_send,
    transpose_lists,
    flatten_lists,
    subscribe_recv,
)


def get_avss_params(n, t):
    from honeybadgermpc.betterpairing import G1, ZR
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


def get_avss_params_pyp(n, t):
    from pypairing import G1, ZR
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


@mark.asyncio
async def test_hbacss0(test_router):
    from pypairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss0(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )

    assert recovered_values == values

@mark.asyncio
async def test_hbacss0_share_fault(test_router):
    from pypairing import G1, ZR
    # Injects one invalid share
    class BadDealer(Hbacss0):
        def _get_dealer_msg(self, values, n):
            # Sample B random degree-(t) polynomials of form φ(·)
            # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
            # The same as B (batch_size)
            fault_n = randint(1, n - 1)
            fault_k = randint(1, len(values) - 1)
            secret_count = len(values)
            phi = [None] * secret_count
            commitments = [None] * secret_count
            # BatchPolyCommit
            #   Cs  <- BatchPolyCommit(SP,φ(·,k))
            # TODO: Whether we should keep track of that or not
            r = ZR.random()
            for k in range(secret_count):
                phi[k] = self.poly.random(self.t, values[k])
                commitments[k] = self.poly_commit.commit(phi[k], r)

            ephemeral_secret_key = self.field.random()
            ephemeral_public_key = pow(self.g, ephemeral_secret_key)
            dispersal_msg_list = [None] * n
            witnesses = self.poly_commit.double_batch_create_witness(phi, r)
            for i in range(n):
                shared_key = pow(self.public_keys[i], ephemeral_secret_key)
                phis_i = [phi[k](i + 1) for k in range(secret_count)]
                if i == fault_n:
                    phis_i[fault_k] = ZR.random()
                z = (phis_i, witnesses[i])
                zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
                dispersal_msg_list[i] = zz
                dispersal_msg_list[i] = zz

            return dumps((commitments, ephemeral_public_key)), dispersal_msg_list

    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = []
        for i in range(n):
            if i == dealer_id:
                hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            else:
                hbavss = Hbacss0(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list.append(hbavss)
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()
    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )
    assert recovered_values == values


@mark.asyncio
async def test_hbacss1(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    #g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    crs = gen_pc_const_dl_crs(t, g=g)
    pc = PolyCommitConstDL(crs)

    values = [ZR.random()] * 2 * (t + 1)
    print("values", values)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    async def multi_dealer(self, dealer_id, pks, sks, n, t, pc):
        print("dealer_id", dealer_id)
        shares = [None] * n
        with ExitStack() as stack:
            hbavss_list = [None] * n
            for i in range(n):
                hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
                hbavss_list[i] = hbavss
                stack.enter_context(hbavss)
                if i == dealer_id:
                    avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
                else:
                    avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
                avss_tasks[i].add_done_callback(print_exception_callback)
            outputs = await asyncio.gather(
                *[hbavss_list[i].output_queue.get() for i in range(n)]
            )
            shares = [output[2] for output in outputs]
            for task in avss_tasks:
                task.cancel()

        fliped_shares = list(map(list, zip(*shares)))
        recovered_values = []
        for item in fliped_shares:
            recovered_values.append(
                polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
            )

        assert recovered_values == values

    self.multi_dealer(dealer_id, pks, sks, n, t, pc)

    '''
    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )

    assert recovered_values == values
    '''
@mark.asyncio
async def test_hbacss1_share_fault(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    # Injects one invalid share
    class BadDealer(Hbacss1):
        def _get_dealer_msg(self, values, n):
            # Sample B random degree-(t) polynomials of form φ(·)
            # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
            # The same as B (batch_size)
            fault_n = randint(1, n - 1)
            fault_k = randint(1, len(values) - 1)
            secret_count = len(values)
            phi = [None] * secret_count
            commitments = [None] * secret_count
            # BatchPolyCommit
            #   Cs  <- BatchPolyCommit(SP,φ(·,k))
            # TODO: Whether we should keep track of that or not
            r = ZR.random()
            for k in range(secret_count):
                phi[k] = self.poly.random(self.t, values[k])
                commitments[k] = self.poly_commit.commit(phi[k], r)

            ephemeral_secret_key = self.field.random()
            ephemeral_public_key = pow(self.g, ephemeral_secret_key)
            dispersal_msg_list = [None] * n
            witnesses = self.poly_commit.double_batch_create_witness(phi, r)
            for i in range(n):
                shared_key = pow(self.public_keys[i], ephemeral_secret_key)
                phis_i = [phi[k](i + 1) for k in range(secret_count)]
                if i == fault_n:
                    phis_i[fault_k] = ZR.random()
                z = (phis_i, witnesses[i])
                zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
                dispersal_msg_list[i] = zz
                dispersal_msg_list[i] = zz

            return dumps((commitments, ephemeral_public_key)), dispersal_msg_list

    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    #g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    crs = gen_pc_const_dl_crs(t, g=g)
    pc = PolyCommitConstDL(crs)

    values = [ZR.random()] * 3 * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = []
        for i in range(n):
            if i == dealer_id:
                hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            else:
                hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i],pc=pc)
            hbavss_list.append(hbavss)
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)

        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        print("outputs", outputs)
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()
    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )
    assert recovered_values == values

@mark.asyncio
async def test_hbacss2(test_router):
    from pypairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * 2 * (t + 1)

    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss2(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )

    assert recovered_values == values

@mark.asyncio
async def test_hbacss2_share_fault(test_router):
    from pypairing import G1, ZR
    from honeybadgermpc.share_recovery import poly_lagrange_at_x, poly_interpolate_at_x
    # Injects one invalid share
    class BadDealer(Hbacss2):
        def _get_dealer_msg(self, values, n):
            # Notice we currently required the number of values shared to be divisible by t+1.
            secret_count = len(values)
            redundant_poly_count = secret_count // (self.t + 1) * (n - (self.t + 1))
            r = ZR.random()
            phis = [self.poly.random(self.t, values[k]) for k in range(secret_count)]
            psis = []
            orig_poly_commitments = [self.poly_commit.commit(phis[k], r) for k in range(secret_count)]
            for batch_idx in range(secret_count // (self.t + 1)):
                base_idx = batch_idx * (self.t + 1)
                known_polys = [[i + 1, phis[base_idx + i]] for i in range(self.t + 1)]
                psis.extend([poly_interpolate_at_x(self.poly, known_polys, i + 1) for
                             i in
                             range(self.t + 1, self.n)])
            redundant_poly_commitments = [self.poly_commit.commit(psis[k], r) for k in range(redundant_poly_count)]

            ephemeral_secret_key = self.field.random()
            ephemeral_public_key = pow(self.g, ephemeral_secret_key)
            dispersal_msg_list = [None] * n
            orig_poly_witnesses = [self.poly_commit.double_batch_create_witness(phis[i::(self.t + 1)], r) for i in
                                   range(self.t + 1)]
            redundant_poly_witnesses = [self.poly_commit.double_batch_create_witness(psis[i::(n - (self.t + 1))], r) for
                                        i
                                        in
                                        range(n - (self.t + 1))]
            fault_i = randint(1, n - 1)
            # fault_i = 4
            fault_k = randint(1, secret_count - 1)
            for i in range(n):
                shared_key = pow(self.public_keys[i], ephemeral_secret_key)
                orig_shares = [phis[k](i + 1) for k in range(secret_count)]
                if i == fault_i:
                    orig_shares[fault_k] = ZR.random()
                # redundant_shares = [psis[k](i + 1) for k in range(redundant_poly_count)]
                # Redundant shares are not required to send.
                z = (orig_shares, [orig_poly_witnesses[j][i] for j in range(self.t + 1)],
                     [redundant_poly_witnesses[j][i] for j in range(n - (self.t + 1))])
                zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
                dispersal_msg_list[i] = zz

            return dumps((orig_poly_commitments, redundant_poly_commitments, ephemeral_public_key)), dispersal_msg_list

    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * 2 * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = []
        for i in range(n):
            if i == dealer_id:
                hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            else:
                hbavss = Hbacss2(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list.append(hbavss)
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )
    # print(values)
    # print("\n\n\n\n")
    assert recovered_values == values


@mark.asyncio
async def test_hbacss1_kzg(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    alpha = ZR.random()
    #g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    #crs = gen_pc_const_crs(t, g=g)
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)


    beta = [None] * n
    for i in range(n):
        beta[i] = ZR.random()

    pc = PolyCommitConst(crs)

    values = [ZR.random()] * 2 * (t + 1)

    avss_tasks = [None] * n
    #dealer_id = randint(0, n - 1)

    async def multi_dealer(dealer_id, pks, sks, n, t, pc):
        print("dealer_id", dealer_id)
        shares = [None] * n
        with ExitStack() as stack:
            hbavss_list = [None] * n
            for i in range(n):
                hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
                hbavss_list[i] = hbavss
                stack.enter_context(hbavss)
                if i == dealer_id:
                    avss_tasks[i] = asyncio.create_task(hbavss.avss(0, i, values=values))
                else:
                    avss_tasks[i] = asyncio.create_task(hbavss.avss(0, i, dealer_id=dealer_id))
                avss_tasks[i].add_done_callback(print_exception_callback)
            outputs = await asyncio.gather(
                *[hbavss_list[i].output_queue.get() for i in range(n)]
            )
            shares = [output[2] for output in outputs]
            for task in avss_tasks:
                task.cancel()

        fliped_shares = list(map(list, zip(*shares)))
        recovered_values = []
        for item in fliped_shares:
            recovered_values.append(
                polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
            )

        assert recovered_values == values
        return [output[3] for output in outputs]

    # shares[i][j] = (dealer_id = i, client_id = j, (commitments, shares, auxes, witness))  for i in range(n)
    shares = [None] * n
    for i in range(0, n):
        shares[i] = await multi_dealer(i, pks, sks, n, t, pc)

    #test shares

    #for i in range(n):
    #    assert pc.batch_verify_eval(shares[0][i]['com'], i+1, shares[0][i]['shares'], shares[0][i]['auxes'], shares[0][i]['wit'])

    #agreement on a set T with size of t + 1
    agr_set = [0, 1, 3]


    def gen_vm_matrix(beta, set):
        dim = len(set)
        vm_mat = [[None] * dim ]* dim
        for j in range(dim):
            for i in range(dim):
                vm_mat[j][i] = beta[set[i]] ** i
        return vm_mat

    vm_matrix = gen_vm_matrix(beta, agr_set)

    def get_shares_of_agr_set_dealer(i, shares, set):
        person_share = [None] * len(set)
        person_com = [None] * len(set)
        person_aux = [None] * len(set)
        person_wit = [None] * len(set)
        for j in range(len(set)):
            person_share[j] = shares[set[j]][i]['shares']
            person_com[j] = shares[set[j]][i]['com']
            person_aux[j] = shares[set[j]][i]['auxes']
            person_wit[j] = shares[set[j]][i]['wit']
        return person_com, person_share, person_aux, person_wit

    person_shs = [None] * n
    person_coms = [None] * n
    person_auxes = [None] * n
    person_wits = [None] * n
    for i in range(n):
        person_coms[i], person_shs[i], person_auxes[i], person_wits[i] = get_shares_of_agr_set_dealer(i, shares, agr_set)


    for i in range(n):
        for j in range(len(agr_set)):
            assert pc.batch_verify_eval(person_coms[i][j], i+1, person_shs[i][j], person_auxes[i][j], person_wits[i][j])



    def mat_mul(A, B):
        dim_row = len(A)
        dim_col = len(B[0])
        res = [[ZR(0) for i in range(dim_col)] for j in range(dim_row)]
        for i in range(dim_row):
            for j in range(dim_col):
                for k in range(dim_row):
                    res[i][j] += A[i][k] * B[k][j]
        return res

    def dot_pow(B_in_zp, A_in_G1):
        dim_row = len(B_in_zp)
        dim_col = len(A_in_G1[0])
        res = [[G1.identity(0) for i in range(dim_col)] for j in range(dim_row)]
        for i in range(dim_row):
            for j in range(dim_col):
                for k in range(dim_row):
                    #print("i, j, k", i, j , k)
                    #print("A", A_in_G1[k][j])
                    #print("B", B_in_zp[i][k])
                    res[i][j] *= A_in_G1[k][j] ** B_in_zp[i][k]
        return res


    random_coms = [None] * n
    random_shares = [None] * n
    random_auxes = [None] * n
    random_wits = [None] * n
    for i in range(n):
        random_shares[i] = mat_mul(vm_matrix, person_shs[i])
        random_auxes[i] = mat_mul(vm_matrix, person_auxes[i])
        random_coms[i] = dot_pow(vm_matrix, person_coms[i])
        random_wits[i] = dot_pow(vm_matrix, person_wits[i])

    assert len(random_shares) == n
    assert len(random_shares[0]) == len(agr_set)
    assert len(random_shares[0][0]) == len(values)

    assert len(random_auxes) == n
    assert len(random_auxes[0]) == len(agr_set)
    assert len(random_auxes[0][0]) == len(values)

    assert len(random_coms) == n
    assert len(random_coms[0]) == len(agr_set)
    assert len(random_coms[0][0]) == len(values)

    assert len(random_wits) == n
    assert len(random_wits[0]) == len(agr_set)
    assert len(random_wits[0][0]) == len(values)

    #print("com[0]", random_coms[0])
    #print("com[1]", random_coms[1])
    for i in range(n):
        for j in range(len(agr_set)):
            for k in range(len(values)):
                assert pc.verify_eval(random_coms[i][j][k], i+1, random_shares[i][j][k], random_auxes[i][j][k], random_wits[i][j][k])

    print("random sharing")




@mark.asyncio
async def test_hbacss1_share_fault_kzg(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    # Injects one invalid share
    class BadDealer(Hbacss1):
        def _get_dealer_msg(self, values, n):
            # Sample B random degree-(t) polynomials of form φ(·)
            # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
            # The same as B (batch_size)
            fault_n = randint(1, n - 1)
            fault_k = randint(1, len(values) - 1)
            secret_count = len(values)
            phi = [None] * secret_count
            commitments = [None] * secret_count
            phi_hat = [None] * secret_count
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
            #witnesses = self.poly_commit.double_batch_create_witness(phi, r)
            for i in range(n):
                shared_key = pow(self.public_keys[i], ephemeral_secret_key)
                phis_i = [phi[k](i + 1) for k in range(secret_count)]
                phi_hats_i = [phi_hat[k](i + 1) for k in range(secret_count)]
                if i == fault_n:
                    phis_i[fault_k] = ZR.random()
                #z = (phis_i, witnesses[i])
                z = (phis_i, phi_hats_i, witnesses[i + 1])
                zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
                #dispersal_msg_list[i] = zz
                dispersal_msg_list[i] = zz

            return dumps((commitments, ephemeral_public_key)), dispersal_msg_list

    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    #g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)

    alpha = ZR.random()

    #crs = gen_pc_const_dl_crs(t, g=g)
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)
    #pc = PolyCommitConstDL(crs)
    pc = PolyCommitConst(crs)

    values = [ZR.random()] * 3 * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = []
        for i in range(n):
            if i == dealer_id:
                hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            else:
                hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i],pc=pc)
            hbavss_list.append(hbavss)
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        #print("outputs", outputs)
        shares = [output[2] for output in outputs]
        for task in avss_tasks:
            task.cancel()
    #print("shares", shares)
    #print("shares_types", type(shares[0][0]))
    fliped_shares = list(map(list, zip(*shares)))
    #print("fliped_shares", fliped_shares)
    #print("fliped_shares_types", type(fliped_shares[0][0]))
    shares_zp = [output[3] for output in outputs]
    # auxes_zp = [output[4] for output in outputs]

    # share_zp[i] = (commitments, shares, auxes, witness)  for i in range(n)
    assert n == len(shares_zp)
    assert len(values) == len(shares_zp[0][0])
    assert len(values) == len(shares_zp[0][1])
    assert len(values) == len(shares_zp[0][2])
    assert len(values) == len(shares_zp[0][3])

    
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )
    assert recovered_values == values


def benchmark_router(n):
    router = SimpleRouter(n)
    return router.sends, router.recvs, router.broadcasts



def _test_router(n, maxdelay=0.005, seed=None):
    """Builds a set of connected channels, with random delay
    @return (receives, sends)
    """
    router = TestRouter(n, maxdelay, seed)
    return router.sends, router.recvs, router.broadcasts

#print(benchmark_router(5))
#test_hbacss0(benchmark_router)
#test_hbacss0(SimpleRouter)
asyncio.run(test_hbacss1_kzg(_test_router))
#asyncio.run(test_hbacss1_kzg(benchmark_router))
#asyncio.run(test_hbacss1_share_fault_kzg(benchmark_router))

