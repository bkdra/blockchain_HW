from FiniteField import *
from EllipticCurves import *

gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
p = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
A = 0
B = 7

class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num = num, prime = p)

class S256Point(Point):
    
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x = S256Field(x), y = S256Field(y), a = a, b = b)
        else: # infinity point
            super().__init__(x = x, y = y, a = a, b = b)
    
    def __rmul__(self, coefficient):
        coefficient = coefficient % N
        return super().__rmul__(coefficient)
    
    def verify(self, z, sig):
        s_inv = pow(sig.s, N-2, N)
        u = (z * s_inv) % N
        v = (sig.r * s_inv) % N
        kG = u * G + v * self
        return kG.x.num == sig.r

G = S256Point(gx, gy)


class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s

class PrivateKey:
    def __init__(self, secret):
        self.secret  = secret
        self.point = secret * G
    
    def sign(self, z, k):
        r = (k * G).x.num
        k_inv = pow(k, N-2, N)
        s = (k_inv * (z + self.secret * r)) % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)


if __name__ == '__main__':
    P = S256Point(0x801be5a7c4faf73dd1c3f28cebf78d6ba7885ead88879b76ffb815d59056af14,
                   0x826ddfcc38dafe6b8d463b609facc009083c8173e21c5fc45b3424964e85f49e)
    z = 0x90d7aecf3f2855d60026f10faab852562c76e7e043cf243474ba5018447c2c22
    r = 0xf01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f
    s = 0x22afcd685b7c0c8b525c2a52529423fcdff22f69f3e9c175ac9cb3ec08de87d8

    sig = Signature(r, s)
    print("pubkey:", P)
    print("sig.r:", hex(sig.r), "\nsig.s:", hex(sig.s))
    if P.verify(z, sig):
        print("Signature is valid")
    else:
        print("Signature is invalid")