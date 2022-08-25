#!/usr/bin/env python3
import unittest
import cryptools


class TestCryptools(unittest.TestCase):

    @staticmethod
    def generate_n(bits):
        p = cryptools.rsa.random_prime(1024)
        q = cryptools.rsa.random_prime(1024)
        return p * q

    def test_rsa_implementation(self):
        p = 997147
        q = 876331
        n = p * q
        m = b"hoge"
        rsa = cryptools.RSA(65537, n, p, q)
        c = rsa.encrypt(cryptools.bytes_to_long(m))
        self.assertNotEqual(m, c)
        flag = rsa.decrypt(c)
        self.assertEqual(cryptools.long_to_bytes(flag), m)

    def test_common_mod(self):
        n = TestCryptools.generate_n(1024)
        e1 = 65537
        e2 = 3

        m = 1234567890123456789012345678901234567890
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)

        self.assertEqual(cryptools.common_modulus_attack(c1, c2, e1, e2, n), m)

    def test_wieners(self):
        n = 0x00d91f0102279d099a9aa3a819faefef8e39e71075c5ed59275ae33fd16f10c6b120fbc14f2b0e85b09b7372853c22b359fb4b850e0b66da55585e1221bc23d4a84bc0cce1c1f1c080c74520c3f7cb2d041bc2c372ae96a3b9344dc00b00a75873fd339121804b39b74969ceab850a5ce8c65860fa1e7cfafb052e994a832198ece195ee8bb427a04609b69f052b1d2818741604e2d1fc95008961365f0536f1d3d12b11f3b56f55aa478b18cc5e74918869d9ef8935ce29c66ac5abdde9cc44b8a33c4a3c057624bee9bdfeb8e296798c377110e2209b68fc500d872fd847fe0a7b41c6826b4db3645133a497424b5c111fc661e320b024bccf4b8120847fc92d
        e = 0x470a2650f57fed98dbde75761701a2b2711c668dcaf1f58c1e87bd1ff21b19ca107bbf8ae7cfdd31e991a6900aa2e4f24ab20fa291fb014a7a7dc73df4726a057a222aa331726cf9b9ebb22e8b8812025340ed1bdf882eef353f009cbf20c1be0e6231c8021d63e82f66c94118cefb1fd3c155bede6037f822992b8e37cd6a1b011aec6dfeb63079030e1af7fabf53bb625a7c58aceaa5805b59495989965cd62440acaa326bb90ba5d315845ad295eced02a8aca56f479c7ed97cb8dbb48b89366cb0467fa77ddfccfd09d428bc4aa6f5170e68a7c219b4c8bd032dc13946e2e1ab5d18e41eddd2dad1d8cef5e7f45dcd9ada2c696dc16f7510b155d7b72c35

        m = 1234567890123456789012345678901234567890
        c = pow(m, e, n)

        d = cryptools.wieners_attack(e, n)
        self.assertEqual(pow(c, d, n), m)

    def test_hasdats(self):
        m = 1234567890123456789012345678901234567890

        e = 17

        # print("collecting e=%d pairs of (c, n)" % e)
        pairs = []
        for i in range(e):
            p = cryptools.random_prime(1024)
            q = cryptools.random_prime(1024)
            n = p * q
            c = pow(m, e, n)
            pairs.append((n, c))

        self.assertEqual(cryptools.hastads_broadcast_attack(e, pairs), m)

    def test_franklin(self):
        e = 3
        n = 0x00d91f0102279d099a9aa3a819faefef8e39e71075c5ed59275ae33fd16f10c6b120fbc14f2b0e85b09b7372853c22b359fb4b850e0b66da55585e1221bc23d4a84bc0cce1c1f1c080c74520c3f7cb2d041bc2c372ae96a3b9344dc00b00a75873fd339121804b39b74969ceab850a5ce8c65860fa1e7cfafb052e994a832198ece195ee8bb427a04609b69f052b1d2818741604e2d1fc95008961365f0536f1d3d12b11f3b56f55aa478b18cc5e74918869d9ef8935ce29c66ac5abdde9cc44b8a33c4a3c057624bee9bdfeb8e296798c377110e2209b68fc500d872fd847fe0a7b41c6826b4db3645133a497424b5c111fc661e320b024bccf4b8120847fc92d

        m1 = 1234567890123456789012345678901234567890
        m2 = m1 + 1

        c1 = pow(m1, e, n)
        c2 = pow(m2, e, n)
        self.assertEqual(cryptools.franklin_reiter_related_message_attack(e, n, c1, c2, 1, 1), m1)

    def test_cca(self):
        n = 0x00a6ef4f3e5aa17855c988a66ce4521cc0221f302cddaf8b10ecd348f27464b465dd7e69983b2cced881bea51b4c6a41a32bc45b2693f89879910c9d332b38ef0ab26c74bff9fa44d6bed1401b8848af669daf4fc4c71902e38b7fd8d0abd364eb4a5f666e818eb342780ab9f177559bd62c0ce9e246b62ac6d982271cbd98e0e8d6c0aab810d3485a156a86193395006527a7d816d07e0fee11d5ea4cf00437ad27fec8dd9023d0133020106162d4d82471a26d5d29888f0221b64cda932dfa1e20c0970cf673b6aff466d583f7c2a48d0785e6334f89f1605e770b10740c13f9c58c010cda4db2c2a216f791aa0196291d832f75fcfc74d55e36980b81f70ca9
        e = 65537
        m = 1234567890123456789012345678901234567890

        def secret(r):
            d = 0x00904ba15acbaa7142ee2e8174f4b3098906b5a0c5d765eab6598f94a986f4997ec7c38271050d894a5a7439716c4f18a77ba88205c9b803cc6915d73828af50e9152b6c8b98ffbccb472bc6d745a9567c43e70af39409c99678b9ace74aef3277b3d4dcccbe8e63e31bb261e217fdd6f37d263870d0209cbf3fba2226d4b836078790e970daf98a2fe23eddcb25089483452f66c9bf6122f5000065b20213d9b268e7dee1aba400cd1a526aa838c53fa2eaec4a40624a651ce0b975c5500f950370aaa48ccfb14151678f0f8b7744fec2bceb9015f5a16dc7ce13d77e3058f7cc3a3778f629e2d9ba121d87bb1c87b3dde88e07bc679cb699bdc39d806b82f281
            c = pow(m, e, n)
            cr = (c * pow(r, e, n)) % n
            mr = pow(cr, d, n)
            return c, mr

        r = 2
        c, mr = secret(r)
        self.assertEqual(cryptools.chosen_ciphertext_attack(e, n, r, mr), m)


if __name__ == '__main__':
    unittest.main()
