from pytest import mark
from random import randint
from contextlib import ExitStack
from pickle import dumps
from honeybadgermpc.polynomial import polynomials_over, EvalPoint
from honeybadgermpc.poly_commit_const_dl import PolyCommitConstDL, gen_pc_const_dl_crs
# from honeybadgermpc.betterpairing import G1, ZR
from honeybadgermpc.hbacss import Hbacss1
from honeybadgermpc.mpc import TaskProgramRunner
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
from honeybadgermpc.utils.misc import print_exception_callback
from honeybadgermpc.field import GF
from honeybadgermpc.elliptic_curve import Subgroup
import asyncio
from functools import reduce
import operator
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

    #values = [ZR.random()] * 2 * (t + 1)

    avss_tasks = [None] * n
    #dealer_id = randint(0, n - 1)

    async def multi_dealer(dealer_id, pks, sks, n, t, pc, values):
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

        if type(values) == tuple:
            assert recovered_values == values[0]
        else:
            assert recovered_values == values

        return [output[3] for output in outputs]

    # shares[i][j] = (dealer_id = i, client_id = j, (commitments, shares, auxes, witness))  for i in range(n)
    shares = [None] * n
    batch_size = 2 * (t + 1)
    for i in range(0, n):
        values = [ZR.random()] * batch_size
        shares[i] = await multi_dealer(i, pks, sks, n, t, pc, values)

    '''
    fliped_coms = [None] * n
    fliped_shares = [None] * n
    fliped_auxes = [None] * n
    fliped_witness = [None] * n
    for i in range(n):
        fliped_coms[i] = list(map(list, zip(*shares[i][0])))
        fliped_shares[i] = list(map(list, zip(*shares[i][1])))
        fliped_coms[i] = list(map(list, zip(*shares[i][0])))
        fliped_coms[i] = list(map(list, zip(*shares[i][0])))
    '''

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
        res = [ZR(0) for i in range(dim_col * dim_row)]
        for i in range(dim_row):
            for j in range(dim_col):
                index = i * dim_col + j
                for k in range(dim_row):
                    res[index] += A[i][k] * B[k][j]
        return res

    def dot_pow(B_in_zp, A_in_G1):
        dim_row = len(B_in_zp)
        dim_col = len(A_in_G1[0])
        res = [G1.identity(0) for i in range(dim_col * dim_row)]
        for i in range(dim_row):
            for j in range(dim_col):
                index = i * dim_col + j
                for k in range(dim_row):
                    res[index] *= A_in_G1[k][j] ** B_in_zp[i][k]
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
    assert len(random_shares[0]) == len(agr_set) * batch_size

    assert len(random_auxes) == n
    assert len(random_auxes[0]) == len(agr_set) * batch_size

    assert len(random_coms) == n
    assert len(random_coms[0]) == len(agr_set) * batch_size

    assert len(random_wits) == n
    assert len(random_wits[0]) == len(agr_set) * batch_size
    # print("com[0]", random_coms[0])
    # print("com[1]", random_coms[1])
    for i in range(n):
        assert pc.batch_verify_eval(random_coms[i], i+1, random_shares[i], random_auxes[i], random_wits[i])
        #assert pc.verify_eval(random_coms[i][j], i + 1, random_shares[i][j], random_auxes[i][j], random_wits[i][j])

    # beaver triples gen
    print("beaver triples generation")
    batch_size_random = int(len(random_shares[0]) / 2)
    print("batch_size",batch_size_random)
    a_shares = [None] * n
    b_shares = [None] * n
    a_coms = [None] * n
    b_coms = [None] * n
    a_auxes = [None] * n
    b_auxes = [None] * n
    a_witness = [None] * n
    b_witness = [None] * n
    c_values = [None] * n
    for i in range(n):
        a_shares[i] = [random_shares[i][j] for j in range(batch_size_random)]
        b_shares[i] = [random_shares[i][j] for j in range(batch_size_random, 2* batch_size_random)]
        c_values[i] = [a_shares[i][j] * b_shares[i][j] for j in range(batch_size_random)]
        a_coms[i] = [random_coms[i][j] for j in range(batch_size_random)]
        b_coms[i] = [random_coms[i][j] for j in range(batch_size_random, 2 * batch_size_random)]
        a_auxes[i] = [random_auxes[i][j] for j in range(batch_size_random)]
        b_auxes[i] = [random_auxes[i][j] for j in range(batch_size_random, 2 * batch_size_random)]
        a_witness[i] = [random_wits[i][j] for j in range(batch_size_random)]
        b_witness[i] = [random_wits[i][j] for j in range(batch_size_random, 2 * batch_size_random)]

    c_shares = [None] * n
    for i in range(n):
        c_shares[i] = await multi_dealer( i, pks, sks, n, t, pc, (c_values[i], (a_coms[i],a_witness[i], a_shares[i], a_auxes[i]), (b_coms[i], b_witness[i], b_shares[i], b_auxes[i])))



    #c_shares[i][j] = (dealer_id = i, client_id = j, (commitments, shares, auxes, witness))  for i in range(n)
    #person_c_shs = [[shares from dealer j] fro j in range(n)]
    # agreement on a set T with size of 2t + 1
    agr_triples_set = [0, 1, 2, 3, 6]

    def lagrange_coefficient(xs, x_recomb=ZR(0)):
        #print(xs)
        vector = []
        #print(enumerate(xs))
        for i, x_i in enumerate(xs):
            #print("i", i, x_i)
            factors = [
                (x_recomb - x_k) / (x_i - x_k) for k, x_k in enumerate(xs) if k != i
            ]
            #print(factors)
            vector.append(reduce(operator.mul, factors))
        #print(vector)
        return vector

    lagrange_coe = lagrange_coefficient([item + 1 for item in agr_triples_set])

    #test the lagrange_coe
    def mysum(iterable):
        i = 0
        for item in iterable:
            if i == 0:
                out = item * 1
            else:
                out += item
            i += 1
        return out

    person_c_shs = [None] * n
    person_c_coms = [None] * n
    person_c_auxes = [None] * n
    person_c_wits = [None] * n

    for i in range(n):
        person_c_coms[i], person_c_shs[i], person_c_auxes[i], person_c_wits[i] = get_shares_of_agr_set_dealer(i,
                                                                                                              c_shares,
                                                                                                              agr_triples_set)

    for i in range(n):
        for j in range(len(agr_triples_set)):
            assert pc.batch_verify_eval(person_c_coms[i][j], i + 1, person_c_shs[i][j], person_c_auxes[i][j],
                                        person_c_wits[i][j])


    #test lagrange_coe
    assert c_values[0][0] == mysum(map(operator.mul, lagrange_coe, [int(person_c_shs[i][0][0]) for i in agr_triples_set]))
    assert c_values[0][0] == mysum(map(operator.mul, lagrange_coe, [person_c_shs[i][0][0] for i in agr_triples_set]))

    #compute c_t_shares
    c_t_shares = [None] * n
    c_t_auxes = [None] * n
    c_t_coms = [None] * n
    c_t_wits = [None] * n

    def degree_reduction(shares, operate1, operate2):
        fliped_shares = list(map(list, zip(*shares)))
        t_shares = [None] * len(fliped_shares)
        i = 0
        for item in fliped_shares:
            t_shares[i] = reduce(operate2, map(operate1, item, lagrange_coe))
            i += 1
        return t_shares

    for i in range(n):
        c_t_shares[i] = degree_reduction(person_c_shs[i], operator.mul, operator.add)
        c_t_auxes[i] = degree_reduction(person_c_auxes[i], operator.mul, operator.add)
        c_t_coms[i] = degree_reduction(person_c_coms[i], operator.pow, operator.mul)
        c_t_wits[i] = degree_reduction(person_c_wits[i], operator.pow, operator.mul)

    #test shares
    for i in range(n):
        assert pc.batch_verify_eval(c_t_coms[i], i+1, c_t_shares[i], c_t_auxes[i], c_t_wits[i])

    # test c = ab
    def test_beaver_triples(a, b, c):
        recovered_a = []
        fliped_a = list(map(list, zip(*a)))
        for item in fliped_a:
            recovered_a.append(polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item)))

        recovered_b = []
        fliped_b = list(map(list, zip(*b)))
        for item in fliped_b:
            recovered_b.append(polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item)))

        recovered_c = []
        fliped_c = list(map(list, zip(*c)))
        for item in fliped_c:
            recovered_c.append(polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item)))

        for i in range(len(recovered_c)):
            assert recovered_c[i] == recovered_a[i] * recovered_b[i]

    test_beaver_triples(a_shares, b_shares, c_t_shares)

    print("Ending of beaver triples generation")



@mark.asyncio
async def test_hbacss1_share_fault_kzg(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    # Injects one invalid share
    class BadDealer(Hbacss1):
        def _get_dealer_msg(self, values_dealer, n):
            # Sample B random degree-(t) polynomials of form φ(·)
            # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
            # The same as B (batch_size)

            flag = True
            if type(values_dealer) == tuple:
                values = values_dealer[0]
                a_info = values_dealer[1]
                b_info = values_dealer[2]
                flag = False
            else:
                values = values_dealer

            secret_count = len(values)
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

            if not flag:
                t = [None] * secret_count
                t_proof = [None] * secret_count
                for i in range(secret_count):
                    t[i], t_proof[i] = self.poly_commit.prove_product(a_info[2][i], a_info[3][i], b_info[2][i],
                                                                      b_info[3][i], phi[i](0), phi_hat[i](0))
                witness_zero_c, com_zero = self.poly_commit.zero_witness(phi, phi_hat)
                aux_info = [(a_info[0], a_info[1]), (b_info[0], b_info[1]), witness_zero_c, t, t_proof]


            for i in range(n):
                shared_key = pow(self.public_keys[i], ephemeral_secret_key)
                phis_i = [phi[k](i + 1) for k in range(secret_count)]
                phi_hats_i = [phi_hat[k](i + 1) for k in range(secret_count)]
                if i == fault_n:
                    phis_i[fault_k] = ZR.random()
                #z = (phis_i, witnesses[i])
                if not flag:
                    z = (phis_i, phi_hats_i, witnesses[i + 1], aux_info)
                else:
                    z = (phis_i, phi_hats_i, witnesses[i + 1])
                zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
                #dispersal_msg_list[i] = zz
                dispersal_msg_list[i] = zz

            return dumps((commitments, ephemeral_public_key, flag, self.my_id)), dispersal_msg_list

    t = 1
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    #g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)

    alpha = ZR.random()

    #crs = gen_pc_const_dl_crs(t, g=g)
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)
    #pc = PolyCommitConstDL(crs)
    pc = PolyCommitConst(crs)

    values_number = (t + 1)

    values = [[None] * values_number] * n
    for i in range(n):
        for j in range(t + 1):
            values[i][j] = ZR.random()
    avss_tasks = [None] * n
    #dealer_id = randint(0, n - 1)

    bad_dealer = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            if i == bad_dealer:
                hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            else:
                hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, i, values=values[i]))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]

        for task in avss_tasks:
            task.cancel()
            # try:
            #     task.cancel()
            # except asyncio.CancelledError and asyncio.concurrent.futures._base.CancelledError:
            #     pass

    share_per_dealer = [[None] *n] * values_number
    for k in range(n):
        recovered_values = []
        for i in range(values_number):
            for j in range(n):
                share_per_dealer[i][j] = shares[j][k][i]
            recovered_values.append(
                polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), share_per_dealer[i])))
        assert recovered_values == values[k]
    print("-----------------Fault sharing-------------------")

    # with ExitStack() as stack:
    #     hbavss_list = []
    #     for i in range(n):
    #         if i == dealer_id:
    #             hbavss = BadDealer(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
    #         else:
    #             hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i],pc=pc)
    #         hbavss_list.append(hbavss)
    #         stack.enter_context(hbavss)
    #         if i == dealer_id:
    #             avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
    #         else:
    #             avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
    #         avss_tasks[i].add_done_callback(print_exception_callback)
    #     outputs = await asyncio.gather(
    #         *[hbavss_list[i].output_queue.get() for i in range(n)]
    #     )
    #     #print("outputs", outputs)
    #     shares = [output[2] for output in outputs]
    #     for task in avss_tasks:
    #         task.cancel()
    # #print("shares", shares)
    # #print("shares_types", type(shares[0][0]))
    # fliped_shares = list(map(list, zip(*shares)))
    # #print("fliped_shares", fliped_shares)
    # #print("fliped_shares_types", type(fliped_shares[0][0]))
    # shares_zp = [output[3] for output in outputs]
    # # auxes_zp = [output[4] for output in outputs]
    #
    # # share_zp[i] = (commitments, shares, auxes, witness)  for i in range(n)
    # assert n == len(shares_zp)
    # assert len(values) == len(shares_zp[0][0])
    # assert len(values) == len(shares_zp[0][1])
    # assert len(values) == len(shares_zp[0][2])
    # assert len(values) == len(shares_zp[0][3])
    #
    #
    # recovered_values = []
    # for item in fliped_shares:
    #     recovered_values.append(
    #         polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
    #     )
    # assert recovered_values == values


async def test_hbacss1_beaver(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    t = 1
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    alpha = ZR.random()
    print(g)
    print(h)
    print(pks)
    print(sks)
    #g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    #crs = gen_pc_const_crs(t, g=g)
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)

    pc = PolyCommitConst(crs)
    values_number = (t + 1)

    values = [[None] * values_number] * n
    for i in range(n):
        for j in range(t+1):
            values[i][j] = ZR.random()

    #values = [[ZR.random()] * (t + 1)] * n
    #print(values)
    avss_tasks = [None] * n

    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss1(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, i, values=values[i]))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]

        for task in avss_tasks:
            task.cancel()

    share_per_dealer = [[None] *n] * values_number
    for k in range(n):
        recovered_values = []
        for i in range(values_number):
            for j in range(n):
                share_per_dealer[i][j] = shares[j][k][i]
            recovered_values.append(
                polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), share_per_dealer[i])))
        assert recovered_values == values[k]

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

#asyncio.run(test_hbacss1_kzg(benchmark_router))
#asyncio.run(test_hbacss1_share_fault_kzg(_test_router))
asyncio.run(test_hbacss1_beaver(_test_router))
