# -*- coding: utf-8 -*-
from gmpy import invert
from .utils import chinese_remainder


class RSA(object):

    def __init__(self, e, n, p, q):
        self.e = e
        self.n = n
        self.p = p
        self.q = q
        self.d = self.get_private_exponent(e, p, q)

    def encrypt(self, m):
        c = pow(m, self.e, self.n)
        return c

    def decrypt(self, c):
        m = pow(c, self.d, self.n)
        return m

    @staticmethod
    def get_private_exponent(e, p, q):
        phi = (p - 1) * (q - 1)
        d = invert(e, phi)
        return d


class MultiPrimeRSA(RSA):

    def __init__(self, e, n, pairs):
        self.e = e
        self.n = n
        self.pairs = pairs
        self.d = self.get_private_exponent(e, pairs)

    def fast_decrypt(self, c):
        n_ary = []
        a_ary = []
        for p, k in self.pairs:
            pk = p ** k
            phi = pk * (p - 1) // p
            d = invert(self.e, phi)
            mk = pow(c, d, pk)
            n_ary.append(pk)
            a_ary.append(mk)
        m = chinese_remainder(zip(n_ary, a_ary))
        return m

    @staticmethod
    def get_private_exponent(e, pairs):
        phi = 1
        for p, k in pairs:
            phi *= (p ** (k - 1) * (p - 1))
        d = invert(e, phi)
        return d
