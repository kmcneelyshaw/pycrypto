# -*- coding: utf-8 -*-
#
#  SelfTest/PublicKey/test_Paillier.py: Self-test for the Paillier primitive
#
# Written in 2011 by Kristen McNeely-Shaw
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""Self-test suite for Crypto.PublicKey.Paillier"""

__revision__ = "$Id$"

import sys
import os
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

import unittest
from Crypto.SelfTest.st_common import list_test_cases, a2b_hex, b2a_hex

class PaillierTest(unittest.TestCase):
    # Test vectors from "RSA-OAEP and RSA-PSS test vectors (.zip file)"
    #   ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip
    # See RSADSI's PKCS#1 page at
    #   http://www.rsa.com/rsalabs/node.asp?id=2125

    # from oaep-int.txt

    # TODO: PyCrypto treats the message as starting *after* the leading "00"
    # TODO: That behaviour should probably be changed in the future.
    plaintext = """
           eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2
        ca 82 31 0b 26 dc d8 7d 5c 68 f1 ee a8 f5 52 67
        c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46 26 f5 af
        f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db
        4c dc fe 4f f4 77 28 b4 a1 b7 c1 36 2b aa d2 9a
        b4 8d 28 69 d5 02 41 21 43 58 11 59 1b e3 92 f9
        82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4f
        7b c2 75 19 52 81 ce 32 d2 f1 b7 6d 4d 35 3e 2d
    """

# TODO: Check this out
    ciphertext = """
        12 53 e0 4d c0 a5 39 7b b4 4a 7a b8 7e 9b f2 a0
        39 a3 3d 1e 99 6f c8 2a 94 cc d3 00 74 c9 5d f7
        63 72 20 17 06 9e 52 68 da 5d 1c 0b 4f 87 2c f6
        53 c1 1d f8 23 14 a6 79 68 df ea e2 8d ef 04 bb
        6d 84 b1 c3 1d 65 4a 19 70 e5 78 3b d6 eb 96 a0
        24 c2 ca 2f 4a 90 fe 9f 2e f5 c9 c1 40 e5 bb 48
        da 95 36 ad 87 00 c8 4f c9 13 0a de a7 4e 55 8d
        51 a7 4d df 85 d8 b5 0d e9 68 38 d6 06 3e 09 55
    """

    modulus = """
        bb f8 2f 09 06 82 ce 9c 23 38 ac 2b 9d a8 71 f7
        36 8d 07 ee d4 10 43 a4 40 d6 b6 f0 74 54 f5 1f
        b8 df ba af 03 5c 02 ab 61 ea 48 ce eb 6f cd 48
        76 ed 52 0d 60 e1 ec 46 19 71 9d 8a 5b 8b 80 7f
        af b8 e0 a3 df c7 37 72 3e e6 b4 b7 d9 3a 25 84
        ee 6a 64 9d 06 09 53 74 88 34 b2 45 45 98 39 4e
        e0 aa b1 2d 7b 61 a5 1f 52 7a 9a 41 f6 c1 68 7f
        e2 53 72 98 ca 2a 8f 59 46 f8 e5 fd 09 1d bd cb
    """

    prime_factor = """
        c9 7f b1 f0 27 f4 53 f6 34 12 33 ea aa d1 d9 35
        3f 6c 42 d0 88 66 b1 d0 5a 0f 20 35 02 8b 9d 86
        98 40 b4 16 66 b4 2e 92 ea 0d a3 b4 32 04 b5 cf
        ce 33 52 52 4d 04 16 a5 a4 41 e7 00 af 46 15 03
    """

    def setUp(self):
        global Paillier, Random, bytes_to_long
        from Crypto.PublicKey import Paillier
        from Crypto import Random
        from Crypto.Util import number
        self.n = number.bytes_to_long(a2b_hex(self.modulus))
        self.p = number.bytes_to_long(a2b_hex(self.prime_factor))

        # Compute q, g, l, m, n_sq
        self.n_sq = self.n*self.n
        self.q = divmod(self.n, self.p)[0]
        self.g = self.n + 1
        self.l = number.LCM(self.p-1, self.q-1)
        self.m = number.inverse(
            divmod(pow(self.g, self.l, self.n_sq)-1, self.n)[0], 
            self.n)

#         # Compute q, d, and u from n, e, and p
#         self.q = divmod(self.n, self.p)[0]
#         self.d = inverse(self.e, (self.p-1)*(self.q-1))
#         self.u = inverse(self.p, self.q)    # u = e**-1 (mod q)

        self.paillier = Paillier

#     def test_generate_1arg(self):
#         """Paillier (default implementation) generated key (1 argument)"""
#         paillierObj = self.paillier.generate(1024)
#         self._check_private_key(paillierObj)
#         self._exercise_primitive(paillierObj)
#         pub = paillierObj.publickey()
#         self.assertEqual(1, pub is not None)
#         assert isinstance(pub, self.paillier.Paillierobj)
#         self._check_public_key(pub)
#         self._exercise_public_primitive(paillierObj)

#     def test_generate_2arg(self):
#         """Paillier (default implementation) generated key (2 arguments)"""
#         paillierObj = self.paillier.generate(1024, Random.new().read)
#         self._check_private_key(paillierObj)
#         self._exercise_primitive(paillierObj)
#         pub = paillierObj.publickey()
#         self.assertEqual(1, pub is not None)
#         assert isinstance(pub, self.paillier.Paillierobj)
#         self._check_public_key(pub)
#         self._exercise_public_primitive(paillierObj)

    def test_construct_2tuple(self):
        """Paillier (default implementation) constructed key (2-tuple)"""
        pub = self.paillier.construct(self.n, self.g)
        self.assertEqual(1, pub is not None)
        assert isinstance(pub, self.paillier.Paillierobj)
        self._check_public_key(pub)
        self._check_encryption(pub)
        self._check_verification(pub)

#     def test_construct_3tuple(self):
#         """Paillier (default implementation) constructed key (3-tuple)"""
#         paillierObj = self.paillier.construct(self.n, self.g, self.l)
#         self._check_private_key(paillierObj)
#         self._check_encryption(paillierObj)
#         self._check_decryption(paillierObj)
# #         self._check_signing(paillierObj)
# #         self._check_verification(paillierObj)

#     def test_construct_4tuple(self):
#         """Paillier (default implementation) constructed key (4-tuple)"""
#         paillierObj = self.paillier.construct(self.n, self.g, self.l, self.m)
#         self._check_private_key(paillierObj)
#         self._check_encryption(paillierObj)
#         self._check_decryption(paillierObj)
# #         self._check_signing(paillierObj)
# #         self._check_verification(paillierObj)

#     def test_construct_5tuple(self):
#         """Paillier (default implementation) constructed key (5-tuple)"""
#         paillierObj = self.paillier.construct(self.n, self.g, self.l, self.m, self.p)
#         self._check_private_key(paillierObj)
#         self._check_encryption(paillierObj)
#         self._check_decryption(paillierObj)
# #         self._check_signing(paillierObj)
# #         self._check_verification(paillierObj)

#     def test_construct_6tuple(self):
#         """Paillier (default implementation) constructed key (6-tuple)"""
#         paillierObj = self.paillier.construct(self.n, self.g, self.l, self.m, self.p, self.q)
#         self._check_private_key(paillierObj)
#         self._check_encryption(paillierObj)
#         self._check_decryption(paillierObj)
# #         self._check_signing(paillierObj)
# #         self._check_verification(paillierObj)

#     def test_construct_7tuple(self):
#         """Paillier (default implementation) constructed key (6-tuple)"""
#         paillierObj = self.paillier.construct(self.n, self.g, self.l, self.m, self.p, self.q, self.n_sq)
#         self._check_private_key(paillierObj)
#         self._check_encryption(paillierObj)
#         self._check_decryption(paillierObj)
# #         self._check_signing(paillierObj)
# #         self._check_verification(paillierObj)

    def _check_private_key(self, paillierObj):
        # Check capabilities
        self.assertEqual(1, paillierObj.has_private())
        #self.assertEqual(1, paillierObj.can_sign())
        self.assertEqual(1, paillierObj.can_encrypt())
        #self.assertEqual(1, paillierObj.can_blind())

#         # Check paillierObj.[nedpqu] -> paillierObj.key.[nedpqu] mapping
#         self.assertEqual(paillierObj.n, paillierObj.key.n)
#         self.assertEqual(paillierObj.e, paillierObj.key.e)
#         self.assertEqual(paillierObj.d, paillierObj.key.d)
#         self.assertEqual(paillierObj.p, paillierObj.key.p)
#         self.assertEqual(paillierObj.q, paillierObj.key.q)
#         self.assertEqual(paillierObj.u, paillierObj.key.u)

        # Sanity check key data
        #self.assertEqual(1, paillierObj.p < paillierObj.q)            # p < q
        self.assertEqual(paillierObj.n, paillierObj.p * paillierObj.q)     # n = pq
        #self.assertEqual(1, paillierObj.d * paillierObj.e % ((paillierObj.p-1) * (paillierObj.q-1))) # ed = 1 (mod (p-1)(q-1))
        #self.assertEqual(1, paillierObj.p * paillierObj.u % paillierObj.q) # pu = 1 (mod q)
        self.assertEqual(1, paillierObj.p > 1)   # p > 1
        self.assertEqual(1, paillierObj.q > 1)   # q > 1
        #self.assertEqual(1, paillierObj.e > 1)   # e > 1
        #self.assertEqual(1, paillierObj.d > 1)   # d > 1

    def _check_public_key(self, paillierObj):
        ciphertext = a2b_hex(self.ciphertext)

        # Check capabilities
        self.assertEqual(0, paillierObj.has_private())
        #self.assertEqual(1, paillierObj.can_sign())
        self.assertEqual(1, paillierObj.can_encrypt())
        #self.assertEqual(1, paillierObj.can_blind())

        # Check paillierObj.[ne] -> paillierObj.key.[ne] mapping
        #self.assertEqual(paillierObj.n, paillierObj.key.n)
        #self.assertEqual(paillierObj.e, paillierObj.key.e)

        # Check that private parameters are all missing
        self.assertEqual(0, hasattr(paillierObj, 'l'))
        self.assertEqual(0, hasattr(paillierObj, 'm'))
        self.assertEqual(0, hasattr(paillierObj, 'p'))
        self.assertEqual(0, hasattr(paillierObj, 'q'))
        #self.assertEqual(0, hasattr(paillierObj.key, 'd'))
        #self.assertEqual(0, hasattr(paillierObj.key, 'p'))
        #self.assertEqual(0, hasattr(paillierObj.key, 'q'))
        #self.assertEqual(0, hasattr(paillierObj.key, 'u'))

         # Public keys should not be able to sign or decrypt
        #self.assertRaises(TypeError, paillierObj.sign, ciphertext, b(""))
        self.assertRaises(TypeError, paillierObj.decrypt, ciphertext)

        # Check __eq__ and __ne__
        self.assertEqual(paillierObj.publickey() == paillierObj.publickey(),True) # assert_
        self.assertEqual(paillierObj.publickey() != paillierObj.publickey(),False) # failIf

    def _exercise_primitive(self, paillierObj):
        # Since we're using a randomly-generated key, we can't check the test
        # vector, but we can make sure encryption and decryption are inverse
        # operations.

        plaintext = a2b_hex(self.plaintext)

        # Test encryption
        ciphertext = paillierObj.encrypt(plaintext, b(""))

        # Test decryption
        new_plaintext2 = paillierObj.decrypt((ciphertext))
        self.assertEqual(b2a_hex(plaintext), b2a_hex(new_plaintext2))


#         ciphertext = a2b_hex(self.ciphertext)

#         # Test decryption
#         plaintext = paillierObj.decrypt((ciphertext,))

#         # Test encryption (2 arguments)
#         (new_ciphertext2,) = paillierObj.encrypt(plaintext, b(""))
#         self.assertEqual(b2a_hex(ciphertext), b2a_hex(new_ciphertext2))

#         # Test blinded decryption
#         blinding_factor = Random.new().read(len(ciphertext)-1)
#         blinded_ctext = paillierObj.blind(ciphertext, blinding_factor)
#         blinded_ptext = paillierObj.decrypt((blinded_ctext,))
#         unblinded_plaintext = paillierObj.unblind(blinded_ptext, blinding_factor)
#         self.assertEqual(b2a_hex(plaintext), b2a_hex(unblinded_plaintext))

#         # Test signing (2 arguments)
#         signature2 = paillierObj.sign(ciphertext, b(""))
#         self.assertEqual((bytes_to_long(plaintext),), signature2)

#         # Test verification
#         self.assertEqual(1, paillierObj.verify(ciphertext, (bytes_to_long(plaintext),)))

    def _exercise_public_primitive(self, paillierObj):
        plaintext = a2b_hex(self.plaintext)

        # Test encryption (2 arguments)
        (new_ciphertext2,) = paillierObj.encrypt(plaintext, b(""))

#         # Exercise verification
#         paillierObj.verify(new_ciphertext2, (bytes_to_long(plaintext),))

    def _check_encryption(self, paillierObj):
        plaintext = a2b_hex(self.plaintext)
        ciphertext = a2b_hex(self.ciphertext)

        # Test encryption (2 arguments)
        (new_ciphertext2,) = paillierObj.encrypt(plaintext, b(""))
        self.assertEqual(b2a_hex(ciphertext), b2a_hex(new_ciphertext2))

    def _check_decryption(self, paillierObj):
        plaintext = a2b_hex(self.plaintext)
        ciphertext = a2b_hex(self.ciphertext)

        # Test plain decryption
        new_plaintext = paillierObj.decrypt((ciphertext,))
        self.assertEqual(b2a_hex(plaintext), b2a_hex(new_plaintext))

#         # Test blinded decryption
#         blinding_factor = Random.new().read(len(ciphertext)-1)
#         blinded_ctext = paillierObj.blind(ciphertext, blinding_factor)
#         blinded_ptext = paillierObj.decrypt((blinded_ctext,))
#         unblinded_plaintext = paillierObj.unblind(blinded_ptext, blinding_factor)
#         self.assertEqual(b2a_hex(plaintext), b2a_hex(unblinded_plaintext))

#     def _check_verification(self, paillierObj):
#         signature = bytes_to_long(a2b_hex(self.plaintext))
#         message = a2b_hex(self.ciphertext)

#         # Test verification
#         t = (signature,)     # paillierObj.verify expects a tuple
#         self.assertEqual(1, paillierObj.verify(message, t))

#         # Test verification with overlong tuple (this is a
#         # backward-compatibility hack to support some harmless misuse of the
#         # API)
#         t2 = (signature, '')
#         self.assertEqual(1, paillierObj.verify(message, t2)) # extra garbage at end of tuple

#     def _check_signing(self, paillierObj):
#         signature = bytes_to_long(a2b_hex(self.plaintext))
#         message = a2b_hex(self.ciphertext)

#         # Test signing (2 argument)
#         self.assertEqual((signature,), paillierObj.sign(message, b("")))


def get_tests(config={}):
    tests = []
    tests += list_test_cases(PaillierTest)
#     try:
#         from Crypto.PublicKey import _fastmath
#         tests += list_test_cases(PaillierFastMathTest)
#     except ImportError:
#         from distutils.sysconfig import get_config_var
#         import inspect
#         _fm_path = os.path.normpath(os.path.dirname(os.path.abspath(
#             inspect.getfile(inspect.currentframe())))
#             +"/../../PublicKey/_fastmath"+get_config_var("SO"))
#         if os.path.exists(_fm_path):
#             raise ImportError("While the _fastmath module exists, importing "+
#                 "it failed. This may point to the gmp or mpir shared library "+
#                 "not being in the path. _fastmath was found at "+_fm_path)
#     tests += list_test_cases(PaillierSlowMathTest)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
