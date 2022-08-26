#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes


def nonce_reuse(known_plaintext, known_ciphertext, ciphertext):
    kct = long_to_bytes(int(known_ciphertext, 16))
    keystream = []
    for p, c in zip(known_plaintext, kct):
        keystream.append(p ^ c)
    keystream = keystream[:len(ciphertext) // 2]
    ct = long_to_bytes(int(ciphertext, 16))
    plaintext = []
    for c, k in zip(ct, keystream):
        plaintext.append(chr(c ^ k))

    return "".join(plaintext)
