# -*- coding: utf-8 -*-

from random import randint
from math import gcd
from ..utils import isqrt, is_square


def small_division(n):
    k = isqrt(n)

    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3

    i = 6
    while i < k:
        if n % (i - 1) == 0:
            return i - 1
        if n % (i + 1) == 0:
            return i + 1
        i += 6


def miller_rabin(n, k=20):
    s, d = 0, n - 1

    while d % 2 == 0:
        s += 1
        d //= 2

    for i in range(k):
        a = randint(2, n - 1)
        x = pow(a, d, n)
        if x == 1:
            continue
        for r in range(s):
            if x == n - 1:
                break
            x = (x * x) % n
        else:
            return False

    return True


def pollard_rho(n):
    is_prime = miller_rabin(n)
    if is_prime:
        print("%d is prime." % n)
        return
    else:
        x, y, d = 2, 2, 1

        while d == 1:
            x = (x * x + 1) % n
            y = (y * y + 1) % n
            y = (y * y + 1) % n
            d = gcd(abs(x - y), n)

        if d != n:
            return d


def fermat(n):
    a = isqrt(n)
    b2 = a * a - n
    while not is_square(b2):
        a += 1
        b2 = a * a - n
    return a - isqrt(b2)
