import pickle
import os
from ctypes import *
import time

import json
lib = CDLL("./gnark-crypto/kzg_ped_out.so")
lib.pyNewSRS.argtypes = [c_int]
lib.pyNewSRS.restype = c_char_p

lib.pyKeyGeneration.argtypes = [c_char_p, c_int]
lib.pyKeyGeneration.restype = c_char_p



def trusted_key_gen(n=4, t=1, seed=None):

    # Generate avss params
    SRS = lib.pyNewSRS(t)
    publicsecretkeys = lib.pyKeyGeneration(SRS, n)

    # Save all keys to files
    if 'keys' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/scripts/keys/')


    # public key of (f+1, n) thld sig
    with open(os.getcwd() + '/scripts/keys/' + 'SRS.key', 'wb') as fp:
        pickle.dump(SRS, fp)

    with open(os.getcwd() + '/scripts/keys/' + 'publicsecretkeys.key', 'wb') as fp:
        pickle.dump(publicsecretkeys, fp)


def load_key(id, N):

    with open(os.getcwd() + '/scripts/keys/' + 'SRS.key', 'rb') as fp:
        SRS = pickle.load(fp)
    
    with open(os.getcwd() + '/scripts/keys/' + 'publicsecretkeys.key', 'rb') as fp:
        publicsecretkeys = pickle.load(fp)


    return SRS, publicsecretkeys


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

    trusted_key_gen(N, f)
    load_key(0, N)
