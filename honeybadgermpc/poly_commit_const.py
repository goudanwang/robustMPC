from honeybadgermpc.betterpairing import ZR, G1, G2, pair
# from pypairing import ZR, G1, G2, pair
from honeybadgermpc.polynomial import polynomials_over
# from pypairing import ZR, G1, hashg1s as hashg1list, hashfrs as hashzrlist, dotprod as inner_product, hashg1sbn as hashg1listbn
import pickle
import math
import hashlib
# from pypairing import py_test, blsmultiexp


class PolyCommitConst:
    def __init__(self, pk, field=ZR):
        assert len(pk) == 3
        (self.gs, self.ghats, self.hs) = pk
        assert len(self.gs) == len(self.hs)
        self.t = len(self.gs) - 1
        #self.gg = self.gs[0].pair_with(self.ghats[0])
        #self.gh = self.hs[0].pair_with(self.ghats[0])
        self.gg = pair(self.gs[0], self.ghats[0])
        self.gh = pair(self.hs[0], self.ghats[0])
        self.field = field

    def commit(self, phi):
        c = G1.identity()
        
        phi_hat = polynomials_over(self.field).random(self.t)
        i = 0
        for item in self.gs:
            c *= item ** phi.coeffs[i]
            i += 1
        i = 0
        for item in self.hs:
            c *= item ** phi_hat.coeffs[i]
            i += 1
        # c should equal g **(phi(alpha)) h **(phi_hat(alpha))

        return c, phi_hat

    # def commit_bls(self, phi, phi_hat=None):
    #     c_g = blsmultiexp(self.gs, phi.coeffs)
        
    #     if phi_hat is None:
    #         phi_hat = polynomials_over(self.field).random(self.t)
    #         c_h = blsmultiexp(self.hs, phi_hat.coeffs)
    #         c = c_g * c_h
    #         return c, phi_hat

    #     c_h = blsmultiexp(self.hs, phi_hat.coeffs)
    #     c = c_g * c_h
    #     return c

    def create_witness(self, phi, phi_hat, i):
        poly = polynomials_over(self.field)
        div = poly([-1 * i, 1])
        # print("-----", type(phi[i]))
        psi = (phi - poly([phi(i)])) / div
        psi_hat = (phi_hat - poly([phi_hat(i)])) / div
        witness = G1.identity()
        j = 0
        for item in self.gs[:-1]:
            witness *= item ** psi.coeffs[j]
            j += 1
        j = 0
        for item in self.hs[:-1]:
            witness *= item ** psi_hat.coeffs[j]
            j += 1
        return witness
    
    # def create_witness_bls(self, phi, phi_hat, i):
    #     poly = polynomials_over(self.field)
    #     div = poly([-1 * i, 1])
    #     psi = (phi - poly([phi(i)])) / div
    #     psi_hat = (phi_hat - poly([phi_hat(i)])) / div
    #     witness_g = blsmultiexp(self.gs[:-1], psi.coeffs)
    #     witness_h = blsmultiexp(self.hs[:-1], psi_hat.coeffs)
    #     witness = witness_g * witness_h
    #     return witness

    def zero_witness(self, phis, phi_hats):
        witness = [None] * len(phis)
        com = [None] * len(phis)
        for i in range(len(phis)):
            witness[i] = self.create_witness(phis[i], phi_hats[i], 0)
            com[i] = self.gs[0] ** phis[i](0) * self.hs[0] ** phi_hats[i](0)
        return witness, com

    def double_batch_create_witness(self, phis, phi_hats, n=None):
        t = len(phis[0].coeffs) - 1
        numpolys = len(phis)
        if n is None:
            n = 3 * t + 1
        witnesses = [[] for _ in range(n+1)]
        #witnesses = []
        #print("n", n)
        for i in range(1, n+1):
            for j in range(len(phis)):
                #print(j)
                witnesses[i].append(self.create_witness(phis[j], phi_hats[j], i))
            #witness.append(temp)
        #witnesses = [ [self.create_witness(phi, phi_hat, i) for phi, phi_hat in phis, phi_hats] for i in range(1, n+1)]
        return witnesses

    # If reusing the same commitment, the lhs of the comparison will be the same.
    # Take advantage of this to save pairings
    def verify_eval(self, c, i, phi_at_i, phi_hat_at_i, witness):
        lhs = pair(c, self.ghats[0])
        rhs = (
            pair(witness, self.ghats[1] * (self.ghats[0] ** -i))
            * self.gg ** phi_at_i
            * self.gh ** phi_hat_at_i
        )
        return lhs == rhs

    def verify_eval_zero_knowledge(self, c, i, share_com, witness):
        lhs = pair(c, self.ghats[0])
        #print(type(share_com))
        #print(type(self.ghats[1] * (self.ghats[0] ** -i)))

        #print(type(share_com))

        rhs = (
            pair(witness, self.ghats[1] * (self.ghats[0] ** -i))
            * pair(share_com, self.ghats[0])
        )
        return lhs == rhs

    def batch_verify_eval(self, commits, i, shares, auxes, witnesses):
        assert (
            len(commits) == len(shares)
            and len(commits) == len(witnesses)
            and len(commits) == len(auxes)
        )
        commitprod = G1.identity()
        witnessprod = G1.identity()
        sharesum = ZR(0)
        auxsum = ZR(0)
        for j in range(len(commits)):
            #print(j)
            commitprod *= commits[j]
            witnessprod *= witnesses[j]
            sharesum += shares[j]
            auxsum += auxes[j]
        lhs = pair(commitprod, self.ghats[0])
        rhs = (
            pair(witnessprod, self.ghats[1] * self.ghats[0] ** (-i))
            * (self.gg ** sharesum)
            * (self.gh ** auxsum)
        )
        return lhs == rhs

    def batch_verify_eval_all(self, commits, i, shares, auxes, witnesses):
        assert (
            len(commits) == len(shares)
            and len(commits) == len(witnesses)
            and len(commits) == len(auxes)
        )
        commitprod = G1.identity()
        witnessprod = G1.identity()
        sharesum = ZR(0)
        auxsum = ZR(0)
        for j in range(len(commits)):
            print(commits[j])
            print("j",j)
            for k in range(len(commits[0])):
                commitprod *= commits[j][k]
                witnessprod *= witnesses[j][k]
                sharesum += shares[j][k]
                auxsum += auxes[j][k]
        lhs = pair(commitprod, self.ghats[0])
        rhs = (
            pair(witnessprod, self.ghats[1] * self.ghats[0] ** (-i))
            * (self.gg ** sharesum)
            * (self.gh ** auxsum)
        )
        return lhs == rhs

    def batch_verify_eval_zero_knowledge(self, commits, i, com_shares, witnesses):
        assert (
            len(commits) == len(com_shares)
            and len(commits) == len(witnesses)
        )
        commitprod = G1.identity()
        witnessprod = G1.identity()
        com_share_prod = G1.identity()
        for j in range(len(commits)):
            commitprod *= commits[j]
            witnessprod *= witnesses[j]
            com_share_prod *= com_shares[j]
        lhs = pair(commitprod, self.ghats[0])
        rhs = (
            pair(witnessprod, self.ghats[1] * self.ghats[0] ** (-i))
            * pair(com_share_prod, self.ghats[0])
        )
        return lhs == rhs

    def preprocess_verifier(self, level=4):
        self.gg.preprocess(level)
        self.gh.preprocess(level)

    def preprocess_prover(self, level=4):
        for item in self.gs:
            item.preprocess(level)
        for item in self.hs:
            item.preprocess(level)

    def prove_product(self, a, a_hat, b, b_hat, c, c_hat):
        e = [ZR.random()] * 5
        T = [None] * 3
        T_proof = [None] *2
        T_proof[0] = [None] * 3
        T_proof[1] = [None] * 5
        T[0] = self.gs[0] ** a * self.hs[0] ** a_hat
        T[1] = self.gs[0] ** b * self.hs[0] ** b_hat
        T[2] = self.gs[0] ** c * self.hs[0] ** c_hat
        #beta
        T_proof[0][0] = self.gs[0] ** e[0] * self.hs[0] ** e[1]
        #gamma
        T_proof[0][1] = self.gs[0] ** e[2] * self.hs[0] ** e[3]
        #delta
        T_proof[0][2] = T[0] ** e[2] * self.hs[0] ** e[4]

        #compute a challenge
        #transcript = pickle.dumps(beta + gamma + delta)
        transcript = pickle.dumps(T_proof[0])
        x = ZR.hash(transcript)

        T_proof[1][0] = e[0] + x * a   #z1
        T_proof[1][1] = e[1] + x * a_hat   #z2
        T_proof[1][2] = e[2] + x * b  #z3
        T_proof[1][3] = e[3] + x * b_hat  #z4
        T_proof[1][4] = e[4] + x * (c_hat - a_hat * b)  #z5

        return T, T_proof


    def verify_product(self, T, T_proof):
        transcript = pickle.dumps(T_proof[0])
        x = ZR.hash(transcript)

        assert T_proof[0][0] * T[0] ** x == self.gs[0] ** T_proof[1][0] * self.hs[0] ** T_proof[1][1]

        assert T_proof[0][1] * T[1] ** x == self.gs[0] ** T_proof[1][2] * self.hs[0] ** T_proof[1][3]

        assert T_proof[0][2] * T[2] ** x == T[0] ** T_proof[1][2] * self.hs[0] ** T_proof[1][4]

        return True







def gen_pc_const_crs(t, alpha=None, g=None, h=None, ghat=None):
    nonetype = type(None)
    assert type(t) is int
    assert type(alpha) in (ZR, int, nonetype)
    assert type(g) in (G1, nonetype)
    assert type(h) in (G1, nonetype)
    assert type(ghat) in (G2, nonetype)
    if alpha is None:
        alpha = int(ZR.random())
    if g is None:
        g = G1.rand([0, 0, 0, 1])
    if h is None:
        h = G1.rand([0, 0, 0, 1])
    if ghat is None:
        ghat = G2.rand([0, 0, 0, 1])
    (gs, ghats, hs) = ([], [], [])
    for i in range(t + 1):
        gs.append(g ** (alpha ** i))
    for i in range(2):
        ghats.append(ghat ** (alpha ** i))
    for i in range(t + 1):
        hs.append(h ** (alpha ** i))
    crs = [gs, ghats, hs]
    return crs
