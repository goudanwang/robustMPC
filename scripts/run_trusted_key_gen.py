import pickle
import os
# from pypairing import ZR, G1, G2, PyFqRepr, PyFq2
from honeybadgermpc.serializer import serialize
from honeybadgermpc.betterpairing import ZR, G1, G2, pair


def get_avss_params(n, t):
    alpha, g, h, ghat = ZR.random(), G1.rand(), G1.rand(), G2.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return alpha, g, ghat, h, public_keys, private_keys



def trusted_key_gen(n=4, t=1, seed=None):

    # Generate avss params
    alpha, g, ghat, h, pks, sks = get_avss_params(n, t)


    for i in range(n):
        print(i, sks[i])

    # Save all keys to files
    if 'keys' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/scripts/keys/')


    # public key of (f+1, n) thld sig
    with open(os.getcwd() + '/scripts/keys/' + 'alpha.key', 'wb') as fp:
        pickle.dump(alpha, fp)

    with open(os.getcwd() + '/scripts/keys/' + 'g.key', 'wb') as fp:
        pickle.dump(g, fp)

    
    with open(os.getcwd() + '/scripts/keys/' + 'ghat.key', 'wb') as fp:
        print("aaaaaaaaaaaaaaa", type(ghat))
        pickle.dump(ghat, fp)

    # public key of (n-f, n) thld sig
    with open(os.getcwd() + '/scripts/keys/' + 'h.key', 'wb') as fp:
        pickle.dump(h, fp)

    # private key of (f+1, n) thld sig
    for i in range(N):
        with open(os.getcwd() + '/scripts/keys/' + 'pks' + str(i) + '.key', 'wb') as fp:
            pickle.dump(pks[i], fp)
            print("=======")


    # private key of (n-f, n) thld sig
    for i in range(N):
        with open(os.getcwd() + '/scripts/keys/' + 'sks' + str(i) + '.key', 'wb') as fp:
            print("afadf")
            pickle.dump(sks[i], fp)


def load_key(id, N):

    with open(os.getcwd() + '/scripts/keys/' + 'g.key', 'rb') as fp:
        g = pickle.load(fp)
    
    with open(os.getcwd() + '/scripts/keys/' + 'g.key', 'rb') as fp:
        g = pickle.load(fp)

    with open(os.getcwd() + '/scripts/keys/' + 'h.key', 'rb') as fp:
        h = pickle.load(fp)
    
    with open(os.getcwd() + '/scripts/keys/' + 'sks' + str(id) + '.key', 'rb') as fp:
        sk = pickle.load(fp)
        print("load----", type(sk))

    pks = []
    for i in range(N):
        with open(os.getcwd() + '/scripts/keys/' + 'pks' + str(i) + '.key', 'rb') as fp:
            pks.append(pickle.load(fp))

    

    return g, h, pks, sk


if __name__ == '__main__':
    
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', metavar='N', required=True,
                        help='number of parties', type=int)
    parser.add_argument('--f', metavar='f', required=True,
                        help='number of faulties', type=int)
    args = parser.parse_args()

    N = args.N
    f = args.f

    assert N >= 3 * f + 1

    trusted_key_gen()
    load_key(0, N)
