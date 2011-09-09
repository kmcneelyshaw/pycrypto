#
#   Paillier.py : Paillier encryption/decryption and signatures
#
#  Part of the Python Cryptography Toolkit
#
#  Written by Kristen McNeely-Shaw based on work of Mike Ivanov
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

__revision__ = "$Id$"

from Crypto.PublicKey.pubkey import *
from Crypto.Util import number

class error (Exception):
    pass

# Generate a Paillier key with N bits
def generate(bits, randfunc, progress_func=None):
    """generate(bits:int, randfunc:callable, progress_func:callable)

    Generate a Paillier key of length 'bits', using 'randfunc' to get
    random data and 'progress_func', if present, to display
    the progress of the key generation.
    """
    if bits < 1024 or (bits & 0xff) != 0:
        # pubkey.getStrongPrime doesn't like anything that's not a multiple of 128 and > 512
        raise ValueError("Paillier modulus length must be a multiple of 256 and > 1024")
    obj=Paillierobj()

    # Generate the prime factors of n
    if progress_func:
        progress_func('p,q\n')
    p = q = 1L
    while number.size(p*q) < bits:
        # There aren't many odd numbers that are a multiple of 256 and > 1024
        p = pubkey.getStrongPrime(bits>>1, 0, 1e-12, randfunc)
        q = pubkey.getStrongPrime(bits - (bits>>1), 0, 1e-12, randfunc)

    # p shall be smaller than q (for calc of u)
    if p > q:
        (p, q)=(q, p)
    obj.p = p
    obj.q = q

# Paillier key generation yields PrivateKey(p,q,n) and PublicKey(n)
#    where PrivateKey has 
#       l(ambda)=(p-1)*(q-1) which is ideally 
#            lcm((p-1),(q-1)) but this bigger one works and 
#       m(u) is the inverse of l modulo n
#    and PublicKey has n, n^2, and g=n+1 (or actually random g ...)
# get g by picking random 0 <= k < n and taking k*n+1
# where "of length bits" is p of length bits/2 and q of same?
# so in other words I have ((l, m),(n, n^2, g))




#     # Generate random number g
#     if progress_func:
#         progress_func('g\n')
#     size=bits-1-(ord(randfunc(1)) & 63) # g will be from 1--64 bits smaller than p
#     if size<1:
#         size=bits-1
#     while (1):
#         obj.g=bignum(getPrime(size, randfunc))
#         if obj.g < obj.p:
#             break
#         size=(size+1) % bits
#         if size==0:
#             size=4
#     # Generate random number x
#     if progress_func:
#         progress_func('x\n')
#     while (1):
#         size=bits-1-ord(randfunc(1)) # x will be from 1 to 256 bits smaller than p
#         if size>2:
#             break
#     while (1):
#         obj.x=bignum(getPrime(size, randfunc))
#         if obj.x < obj.p:
#             break
#         size = (size+1) % bits
#         if size==0:
#             size=4
#     if progress_func:
#         progress_func('y\n')
#     obj.y = pow(obj.g, obj.x, obj.p)
#     return obj

def construct(tuple):
    """construct(tuple:(long,long,long,long,long)))
             : Paillierobj
    Construct a Paillier key from a 5-tuple of numbers.
    """

    obj=Paillierobj()
    if len(tuple) not in [5]:
        raise ValueError('argument for construct() wrong length')
    for i in range(len(tuple)):
        field = obj.keydata[i]
        setattr(obj, field, tuple[i])
    return obj

class Paillierobj(pubkey):
    #keydata=['p', 'g', 'y', 'x']
    keydata=['l', 'm', 'n', 'n_sq', 'g']
    def _encrypt(self, M, K):
        a=pow(self.g, K, self.p)
        b=( M*pow(self.y, K, self.p) ) % self.p
        return ( a,b )

    def _decrypt(self, M):
        if (not hasattr(self, 'x')):
            raise TypeError('Private key not available in this object')
        ax=pow(M[0], self.x, self.p)
        plaintext=(M[1] * inverse(ax, self.p ) ) % self.p
        return plaintext

    def _sign(self, M, K):
        if (not hasattr(self, 'x')):
            raise TypeError('Private key not available in this object')
        p1=self.p-1
        if (GCD(K, p1)!=1):
            raise ValueError('Bad K value: GCD(K,p-1)!=1')
        a=pow(self.g, K, self.p)
        t=(M-self.x*a) % p1
        while t<0: t=t+p1
        b=(t*inverse(K, p1)) % p1
        return (a, b)

    def _verify(self, M, sig):
        v1=pow(self.y, sig[0], self.p)
        v1=(v1*pow(sig[0], sig[1], self.p)) % self.p
        v2=pow(self.g, M, self.p)
        if v1==v2:
            return 1
        return 0

    def size(self):
        "Return the maximum number of bits that can be handled by this key."
        return number.size(self.p) - 1

    def has_private(self):
        """Return a Boolean denoting whether the object contains
        private components."""
        if hasattr(self, 'x'):
            return 1
        else:
            return 0

    def publickey(self):
        """Return a new key object containing only the public information."""
        return construct((self.p, self.g, self.y))


object=Paillierobj

