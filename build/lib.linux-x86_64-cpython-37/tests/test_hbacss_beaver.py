from pytest import mark
from random import randint
from contextlib import ExitStack
from pickle import dumps
from honeybadgermpc.polynomial import polynomials_over, EvalPoint
from honeybadgermpc.hbacss_beaver import Beaver
from honeybadgermpc.hbacss_random_share import Random_share
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
async def test_hbacss1_share_fault_kzg(test_router):
    from pypairing import G1, ZR
    #from honeybadgermpc.betterpairing import G1, ZR
    # Injects one invalid share
    class BadDealer(Random_share):
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


async def test_random_sharings_gen(test_router):
    from pypairing import G1, ZR
    import pickle
    #from honeybadgermpc.betterpairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    alpha = ZR.random()
    sends, recvs, _ = test_router(n)
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)

    pc = PolyCommitConst(crs)
    values_number = (t + 1) * 2

    values = [[None] * values_number] * n
    for i in range(n):
        for j in range(values_number):
            values[i][j] = ZR.random()

    #values = [[ZR.random()] * (t + 1)] * n
    #print(values)
    avss_tasks = [None] * n

    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Random_share(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, i, values=values[i]))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        coms = [output[0] for output in outputs]
        shares = [output[1] for output in outputs]
        auxes = [output[2] for output in outputs]
        witnesses = [output[3] for output in outputs]

        for task in avss_tasks:
            task.cancel()


    for i in range(n):
        assert pc.batch_verify_eval(coms[i], i+1, shares[i], auxes[i], witnesses[i])

    print("Ending of random sharing generation generation")


async def test_beaver_gen(test_router):
    from pypairing import G1, ZR
    import pickle
    #from honeybadgermpc.betterpairing import G1, ZR
    t = 2
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params_pyp(n, t)
    alpha = ZR.random()
    sends, recvs, _ = test_router(n)
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)

    pc = PolyCommitConst(crs)
    values_number = (t + 1) * 2

    values = [[None] * values_number] * n
    for i in range(n):
        for j in range(values_number):
            values[i][j] = ZR.random()

    #values = [[ZR.random()] * (t + 1)] * n
    #print(values)
    avss_tasks = [None] * n

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Random_share(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, i, values=values[i]))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        coms = [output[0] for output in outputs]
        shares = [output[1] for output in outputs]
        auxes = [output[2] for output in outputs]
        witnesses = [output[3] for output in outputs]

        for task in avss_tasks:
            task.cancel()

    for i in range(n):
        assert pc.batch_verify_eval(coms[i], i+1, shares[i], auxes[i], witnesses[i])

    print("Ending of random sharing generation generation")

    print("beaver triples generation")
    batch_size_random = int(len(shares[0]) / 2)
    print("batch_size", batch_size_random)
    beaver_tasks = [None] * n

    beaver_inputs = [[None] * 3] * n
    for i in range(n):
        beaver_inputs[i] = (
            [shares[i][j] * shares[i][j + batch_size_random] for j in range(batch_size_random)],
            ([coms[i][j] for j in range(batch_size_random)],
            [witnesses[i][j] for j in range(batch_size_random)],
            [shares[i][j] for j in range(batch_size_random)],
            [auxes[i][j] for j in range(batch_size_random)]),
            ([coms[i][j] for j in range(batch_size_random, 2 * batch_size_random)],
             [witnesses[i][j] for j in range(batch_size_random, 2 * batch_size_random)],
             [shares[i][j] for j in range(batch_size_random, 2 * batch_size_random)],
             [auxes[i][j] for j in range(batch_size_random, 2 * batch_size_random)])

        )

    with ExitStack() as stack:
        beaver_list = [None] * n
        for i in range(n):
            beaver = Beaver(pks, sks[i], crs, n, t, i, sends[i], recvs[i], pc=pc)
            beaver_list[i] = beaver
            stack.enter_context(beaver)
            beaver_tasks[i] = asyncio.create_task(beaver.avss(0, i, values=beaver_inputs[i]))
            beaver_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[beaver_list[i].output_queue.get() for i in range(n)]
        )
        c_coms = [output[0] for output in outputs]
        c_shares = [output[1] for output in outputs]
        c_auxes = [output[2] for output in outputs]
        c_witnesses = [output[3] for output in outputs]

        for task in beaver_tasks:
            task.cancel()



    # verify the outputs [ab]
    for i in range(n):
        assert pc.batch_verify_eval(c_coms[i], i + 1, c_shares[i], c_auxes[i], c_witnesses[i])

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
        return True

    a_shares = [beaver_inputs[i][1][2] for i in range(n)]
    b_shares = [beaver_inputs[i][2][2] for i in range(n)]
    if test_beaver_triples(a_shares, b_shares, c_shares):
        print("Beaver triples generation successes!")



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
asyncio.run(test_beaver_gen(_test_router))
