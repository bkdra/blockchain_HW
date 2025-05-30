from FiniteField import *
from EllipticCurves import *
import hashlib

gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
p = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
A = 0
B = 7

class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num = num, prime = p)
    def sqrt(self):
        return self**((p + 1) // 4)

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
    
    def sec(self, compressed = True):
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') +  self.y.num.to_bytes(32, 'big')

    @classmethod
    def parse(self, sec_bin):
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x, y)
        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        alpha = (x**3 + S256Field(B))
        beta = alpha.sqrt()
        if beta.num & 2 == 0:
            even_beta = beta
            odd_beta = S256Field(p - beta.num)
        else:
            odd_beta = beta
            even_beta = S256Field(p - beta.num)
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)

G = S256Point(gx, gy)


class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s
    
    def DER(self):
        r_bin = self.r.to_bytes(32, byteorder = 'big')
        r_bin = r_bin.lstrip(b'\x00')
        if r_bin[0] & 0x80:
            r_bin = b'\x00' + r_bin
        result = bytes([2, len(r_bin)]) + r_bin

        s_bin = self.s.to_bytes(32, byteorder = 'big')
        s_bin = s_bin.lstrip(b'\x00')
        if s_bin[0] & 0x80:
            s_bin = b'\x00' + s_bin
        result += bytes([2, len(s_bin)]) + s_bin
        return bytes([0x30, len(result)]) + result
    
    @classmethod
    def parse(cls, der):
        if der[0] != 0x30:
            raise ValueError(f"Not a DER signature: {der.hex()}")
        if der[1] + 2 != len(der):
            raise ValueError(f"Invalid DER length: {der.hex()}")
        if der[2] != 0x02:
            raise ValueError(f"Invalid DER r: {der.hex()}")
        r_len = der[3]
        r = int.from_bytes(der[4:4+r_len], 'big')
        if der[4+r_len] != 0x02:
            raise ValueError(f"Invalid DER s: {der.hex()}")
        s_len = der[5+r_len]
        s = int.from_bytes(der[6+r_len:6+r_len+s_len], 'big')
        return Signature(r, s)

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

def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


if __name__ == '__main__':
    ### 3-1, 3-2
    e1 = 23396049
    e2 = 23396050
    private_key1 = PrivateKey(e1)
    private_key2 = PrivateKey(e2)
    print("uncompressed SEC format (e = 23396049): ", private_key1.point.sec(compressed = False))
    print("compressed SEC format (e = 23396050): ", private_key2.point.sec())

    ### 3-3
    r = 0x8208f5abf04066bad1db9d46f8bcf5a6cc11d0558ab523e7bd3c0ec08bdb782f 
    s = 0x22afcd685b7c0c8b525c2a52529423fcdff22f69f3e9c175ac9cb3ec08de87d8
    sig = Signature(r, s)
    print("DER format: ", sig.DER())
    # sig2 = Signature.parse(sig.DER())
    # print("r = ", hex(sig2.r))
    # print("s = ", hex(sig2.s))

    