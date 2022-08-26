#!/usr/bin/env python3
from functools import reduce
from gmpy import invert, is_prime
from random import getrandbits


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


# http://rosettacode.org/wiki/Chinese_remainder_theorem#Python
def chinese_remainder(pairs):
    sum = 0
    n = map(lambda x: x[0], pairs)
    prod = reduce(lambda a, b: a * b, n)

    for n_i, a_i in pairs:
        p = prod // n_i
        sum += a_i * invert(p, n_i) * p
    return sum % prod


def random_prime(bits):
    while True:
        n = getrandbits(bits)
        if is_prime(n):
            return n


def isqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def is_square(n):
    if not n % 48 in (0, 1, 4, 9, 16, 25, 33, 36):
        return False

    x = isqrt(n)
    return x * x == n
