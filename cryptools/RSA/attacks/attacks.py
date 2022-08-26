#!/usr/bin/env python3
# Refered:
# - http://inaz2.hatenablog.com/entry/2016/01/15/011138
from gmpy import root, gcdext, invert, is_square
from ..rsa import chinese_remainder


def low_public_exponent_attack(n, c, e):
    bound = root(n, e)[0]
    m = root(c, e)[0]
    return m, bound


def common_modulus_attack(c1, c2, e1, e2, n):
    gcd, s1, s2 = gcdext(e1, e2)
    if s1 < 0:
        s1 = -s1
        c1 = invert(c1, n)
    if s2 < 0:
        s2 = -s2
        c2 = invert(c2, n)
    v = pow(c1, s1, n)
    w = pow(c2, s2, n)
    m = (v * w) % n
    return m


def wieners_attack(e, n):
    def continued_fraction(n, d):
        """
        415/93 = 4 + 1/(2 + 1/(6 + 1/7))

        >>> continued_fraction(415, 93)
        [4, 2, 6, 7]
        """
        cf = []
        while d:
            q = n // d
            cf.append(q)
            n, d = d, n - d * q
        return cf

    def convergents_of_contfrac(cf):
        """
        4 + 1/(2 + 1/(6 + 1/7)) is approximately 4/1, 9/2, 58/13 and 415/93

        >>> list(convergents_of_contfrac([4, 2, 6, 7]))
        [(4, 1), (9, 2), (58, 13), (415, 93)]
        """
        n0, n1 = cf[0], cf[0] * cf[1] + 1
        d0, d1 = 1, cf[1]
        yield (n0, d0)
        yield (n1, d1)

        for i in range(2, len(cf)):
            n2, d2 = cf[i] * n1 + n0, cf[i] * d1 + d0
            yield (n2, d2)
            n0, n1 = n1, n2
            d0, d1 = d1, d2

    cf = continued_fraction(e, n)
    convergents = convergents_of_contfrac(cf)

    for k, d in convergents:
        if k == 0:
            continue
        phi, rem = divmod(e * d - 1, k)
        if rem != 0:
            continue
        s = n - phi + 1
        # check if x^2 - s*x + n = 0 has integer roots
        D = s * s - 4 * n
        if D > 0 and is_square(D):
            return d


def hastads_broadcast_attack(e, pairs):
    x = chinese_remainder(pairs)
    m = root(x, e)[0]
    return m


# https://pdfs.semanticscholar.org/899a/4fdc048102471875e24f7fecb3fb8998d754.pdf
def franklin_reiter_related_message_attack(e, n, c1, c2, a, b):
    assert e == 3 and b != 0
    frac = b * (c2 + 2 * pow(a, 3) * c1 - pow(b, 3))
    denom = a * (c2 - pow(a, 3) * c1 + 2 * pow(b, 3))
    m = (frac * invert(denom, n)) % n
    return m


def chosen_ciphertext_attack(e, n, r, mr):
    m = (mr * invert(r, n)) % n
    return m
