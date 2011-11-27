#
#   PublicKey/Paillier.py : Paillier public key encryption/decryption
#
#  Part of the Python Cryptography Toolkit
#
#  Written in 2011 by Kristen McNeely-Shaw
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

"""Paillier public key cryptography algorithms"""

__revision__ = "$Id$"

#__all__ = ['generate', 'construct', 'error', 'importKey' ]
__all__ = ['generate', 'construct']

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from Crypto.Util import number

class _Paillierobj(pubkey.pubkey):
    keydata = ['n', 'g', 'l', 'm', 'p', 'q', 'n_sq']

    def _encrypt(self, m):
        if not self.has_private():
            raise TypeError("No private key")
        r = _getRandomMult(self)
        return (pow(self.g, m, self.n_sq)*pow(r, self.n, self.n_sq)) % self.n_sq
    
    def _decrypt(self, c):
        return L(pow(c, self.l, self.n_sq), self.n)*self.m % self.n

    def _getRandomMult(self):
        r = self.p # start while loop
        while (r % self.p == 0) or (r % self.q == 0):
            r = number.getRandomRange(1, self.n-1, self._randfunc)
        return r

    def size(self):
        return number.size(self.n) - 1 # TODO: check this

    def has_private(self):
        if hasattr(self, 'l') and hasattr(self, 'm'):
            return 1
        else:
            return 0

    def publickey():
        return construct((self.n, self.g, self.n_sq))
    


def generate(bits, randfunc=None, progress_func=None):
    # TODO: keydata = ['n', 'g', 'l', 'm', 'p', 'q', 'n_sq']
    obj=Paillierobj()
    # Generate the prime factors of n
    if progress_func:
        progress_func('p,q\n')
    p = q = 1L
    assert bits % 2 == 0, "Not an even number of bits"
    while number.size(p*q) < bits:
        p = number.getPrime(bits>>1, randfunc)
        q = number.getPrime(bits>>1, randfunc)

    obj.p = p
    obj.q = q
    obj.n = p*q
    obj.n_sq = n*n

    if progress_func:
        progress_func('l\n')
    obj.l = number.LCM(obj.p-1, obj.q-1)

    if progress_func:
        progress_func('g\n')

    obj.g = obj._getRandomMult()*obj.n+1 # TODO: check
    gExp = L(pow(obj.g, obj.l, obj.n_sq), obj.n)
    while not num.GCD(gExp, obj.n) == 1:
        obj.g = obj._getRandomMult()*obj.n+1 # TODO: check
        gExp = L(pow(obj.g, obj.l, obj.n_sq), obj.n)
    obj.m = number.inverse(gExp, obj.n)

    assert bits <= 1+obj.size(), "Generated key is too small"

    return obj

def L(u, n):
    return (u - 1) // n
    

# # __revision__ = "$Id$"

# # # Paillier key generation yields PrivateKey(p,q,n) and PublicKey(n)
# # #    where PrivateKey has 
# # #       l(ambda)=(p-1)*(q-1) which is ideally 
# # #            lcm((p-1),(q-1)) but this bigger one works and 
# # #       m(u) is the inverse of l modulo n
# # #    and PublicKey has n, n^2, and g=n+1 (or actually random g ...)
# # # get g by picking random 0 <= k < n and taking k*n+1
# # # where "of length bits" is p of length bits/2 and q of same?
# # # so in other words I have ((l, m),(n, n^2, g))




# # #     # Generate random number g
# # #     if progress_func:
# # #         progress_func('g\n')
# # #     size=bits-1-(ord(randfunc(1)) & 63) # g will be from 1--64 bits smaller than p
# # #     if size<1:
# # #         size=bits-1
# # #     while (1):
# # #         obj.g=bignum(getPrime(size, randfunc))
# # #         if obj.g < obj.p:
# # #             break
# # #         size=(size+1) % bits
# # #         if size==0:
# # #             size=4
# # #     # Generate random number x
# # #     if progress_func:
# # #         progress_func('x\n')
# # #     while (1):
# # #         size=bits-1-ord(randfunc(1)) # x will be from 1 to 256 bits smaller than p
# # #         if size>2:
# # #             break
# # #     while (1):
# # #         obj.x=bignum(getPrime(size, randfunc))
# # #         if obj.x < obj.p:
# # #             break
# # #         size = (size+1) % bits
# # #         if size==0:
# # #             size=4
# # #     if progress_func:
# # #         progress_func('y\n')
# # #     obj.y = pow(obj.g, obj.x, obj.p)
# # #     return obj


# # def construct(tuple):
# #     """construct(tuple:(long,long,long,long,long)))
# #              : Paillierobj
# #     Construct a Paillier key from a 5-tuple of numbers.
# #     """

# #     obj=Paillierobj()
# #     if len(tuple) not in [5]:
# #         raise ValueError('argument for construct() wrong length')
# #     for i in range(len(tuple)):
# #         field = obj.keydata[i]
# #         setattr(obj, field, tuple[i])
# #     return obj

# # class Paillierobj(pubkey):
# #     #keydata=['p', 'g', 'y', 'x']
# #     keydata=['l', 'm', 'n', 'n_sq', 'g']
# #     def _encrypt(self, M, K):
# #         a=pow(self.g, K, self.p)
# #         b=( M*pow(self.y, K, self.p) ) % self.p
# #         return ( a,b )

# #     def _decrypt(self, M):
# #         if (not hasattr(self, 'x')):
# #             raise TypeError('Private key not available in this object')
# #         ax=pow(M[0], self.x, self.p)
# #         plaintext=(M[1] * inverse(ax, self.p ) ) % self.p
# #         return plaintext

# #     def _sign(self, M, K):
# #         if (not hasattr(self, 'x')):
# #             raise TypeError('Private key not available in this object')
# #         p1=self.p-1
# #         if (GCD(K, p1)!=1):
# #             raise ValueError('Bad K value: GCD(K,p-1)!=1')
# #         a=pow(self.g, K, self.p)
# #         t=(M-self.x*a) % p1
# #         while t<0: t=t+p1
# #         b=(t*inverse(K, p1)) % p1
# #         return (a, b)

# #     def _verify(self, M, sig):
# #         v1=pow(self.y, sig[0], self.p)
# #         v1=(v1*pow(sig[0], sig[1], self.p)) % self.p
# #         v2=pow(self.g, M, self.p)
# #         if v1==v2:
# #             return 1
# #         return 0

# #     def size(self):
# #         "Return the maximum number of bits that can be handled by this key."
# #         return number.size(self.p) - 1

# #     def has_private(self):
# #         """Return a Boolean denoting whether the object contains
# #         private components."""
# #         if hasattr(self, 'x'):
# #             return 1
# #         else:
# #             return 0

# #     def publickey(self):
# #         """Return a new key object containing only the public information."""
# #         return construct((self.p, self.g, self.y))


# # object=Paillierobj

