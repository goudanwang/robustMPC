import random
from unittest import TestCase

from py_ecc.fields import optimized_bls12_381_FQ as FQ

from prover import create_matrix
from setup import generate_setup
from shared import MODULUS, Sample
from verifier import verify, verify_aggregated

from my_types import G1Point

from typing import Optional

from py_ecc import optimized_bls12_381 as b
from py_ecc.fields import optimized_bls12_381_FQ as FQ, optimized_bls12_381_FQ2 as FQ2

from my_types import G1Point, G2Point

MODULUS = b.curve_order


def setup(maxdegree):
    global _setup
    """
    # Generate trusted setup, in coefficient form.
    # For data availability we always need to compute the polynomials anyway, so it makes little sense to do things in Lagrange space
    """
    _setup = (
        [b.multiply(b.G1, pow(s, i, MODULUS)) for i in range(size + 1)],
        [b.multiply(b.G2, pow(s, i, MODULUS)) for i in range(size + 1)],
    )



if __name__ == '__main__':
    #setup(2)
    print(b.G1)
    print(b.G2)