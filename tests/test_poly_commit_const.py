from honeybadgermpc.betterpairing import G1, ZR
from pypairing import G1, ZR
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_const import PolyCommitConst, gen_pc_const_crs

# from pypairing import py_test, blsmultiexp
import time





def test_pc_const():
    batchsize = 1000
    t = 10
    alpha = int(ZR.random())
    g = G1.rand()
    h = G1.rand()
    crs = gen_pc_const_crs(t)
    pc = PolyCommitConst(crs)
    phi = [None] * batchsize
    for i in range(batchsize):
        phi[i] = polynomials_over(ZR).random(t)
    c = [None] * batchsize
    phi_hat = [None] * batchsize

    begin_time = time.time()
    for i in range(batchsize):
        c[i], phi_hat[i] = pc.commit(phi[i])
    end_time = time.time()
    print(f"time to commit {batchsize} polynomial: {(end_time - begin_time)} in python manner")

    begin_time = time.time()
    for i in range(3 * t + 1):
        _ = pc.create_witness(phi[i], phi_hat[i], i+1)
    end_time = time.time()
    print(f"time to compute {3*t+1} witness: {(end_time - begin_time)} in python manner")


    c_b = [None] * batchsize
    phi_hat_b = [None] * batchsize
    begin_time = time.time()
    for i in range(batchsize):
        c_b[i], phi_hat_b[i] = pc.commit_bls(phi[i])
    end_time = time.time()
    print(f"time to commit {batchsize} polynomial: {(end_time - begin_time)} in rust manner")


    
    begin_time = time.time()
    for i in range(3 * t + 1):
        _ = pc.create_witness_bls(phi[i], phi_hat_b[i], i+1)
    end_time = time.time()
    print(f"time to compute {3*t+1} witness: {(end_time - begin_time)} in python manner")


    # shares = [None] * 3
    # auxes = [None] * 3
    # for i in range(3):
    #     c[i], phi_hat[i] = pc.commit(phi[i])
    #     shares[i] = phi[i](1)
    #     auxes[i] = phi_hat[i](1)
    # #witness = pc.create_witness(phi, phi_hat, 3)
    # print("create witness")
    # witness = pc.double_batch_create_witness(phi, phi_hat)
    # witness_at_zero, com_at_zero = pc.zero_witness(phi,phi_hat)
    # print("witness_at_zero", witness_at_zero)
    # print("witness_at_zero", len(witness_at_zero))
    # print("com", len(shares))
    # print("wit", len(auxes))
    # #assert c[0] == g ** phi[0](alpha) * h ** phi_hat[0](alpha)
    # assert pc.verify_eval(c[1] * c[2], 1, phi[1](1) + phi[2](1), phi_hat[1](1) + phi_hat[2](1), witness[1][1] * witness[1][2])
    # assert not pc.verify_eval(c[0], 2, phi[0](1), phi_hat[0](1), witness[1][0])
    # assert pc.verify_eval(c[1], 1, shares[1], auxes[1], witness[1][1])
    # assert pc.batch_verify_eval(c, 1, shares, auxes, witness[1])
    # print("+++++++++++++++++")
    # assert pc.verify_eval(c[1], 0, phi[1](0), phi_hat[1](0), witness_at_zero[1])

    # temp = [None] *2
    # temp[0] = ZR.random()
    # temp[1] = ZR.random()
    # c_prod = (c[1] ** temp[0]) * (c[2] ** temp[1])
    # phi_sum = phi[1](1) * temp[0] + phi[2](1) *temp[1]
    # phi_hat_sum = phi_hat[1](1) * temp[0] + phi_hat[2](1) * temp[1]
    # wit_prod = (witness[1][1] ** temp[0]) * (witness[1][2] ** temp[1])

    # assert pc.verify_eval(c_prod, 1, phi_sum, phi_hat_sum, wit_prod)

    # assert pc.verify_eval(c[1] * c[2], 1, phi[1](1) + phi[2](1), phi_hat[1](1) + phi_hat[2](1),
    #                       witness[1][1] * witness[1][2])

    # assert pc.verify_eval_zero_knowledge(c[1], 0, com_at_zero[1], witness_at_zero[1])

    # temp = (c[0], c[1])
    # print(type(temp))
    # assert type(temp) == tuple

    '''
    a = ZR.random()
    a_hat = ZR.random()
    b = ZR.random()
    b_hat = ZR.random()
    c = a * b
    c_hat = ZR.random()
    T, T_proof = pc.prove_product(a, a_hat, b, b_hat, c, c_hat)
    pc.verify_product(T, T_proof)

    #c_false = ZR.random()
    #T, T_proof = pc.prove_product(a, a_hat, b, b_hat, c_false, c_hat)
    #pc.verify_product(T, T_proof)

    temp_pro = [None] * 3
    for i in range(len(shares)):
        temp_pro[i] = crs[0][0] ** shares[i] * crs[2][0] ** auxes[0]

    assert pc.batch_verify_eval_zero_knowledge(c, 1, temp_pro, witness[1])
    '''




def test_pc_const_preprocess():
    t = 2
    alpha = ZR.random()
    g = G1.rand()
    h = G1.rand()
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)
    print(crs)
    pc = PolyCommitConst(crs)
    pc.preprocess_prover()
    phi = polynomials_over(ZR).random(t)
    c, phi_hat = pc.commit(phi)
    witness = pc.create_witness(phi, phi_hat, 3)
    assert c == g ** phi(alpha) * h ** phi_hat(alpha)
    pc.preprocess_verifier()
    assert pc.verify_eval(c, 3, phi(3), phi_hat(3), witness)
    assert not pc.verify_eval(c, 4, phi(3), phi_hat(3), witness)

#test_pc_const_preprocess()
#test_pc_const_preprocess()
test_pc_const()
