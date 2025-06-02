from FiniteField import *
from EllipticCurves import *
import hashlib
import random

gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
p = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
A = 0
B = 7
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

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
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(p - beta.num)
        else:
            odd_beta = beta
            even_beta = S256Field(p - beta.num)
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)
    
    def RIPEMD160_SHA256(self, compressed = True):
        return RIPEMD160_SHA256(self.sec(compressed))
    
    def address(self, compressed = True, testnet = False):
        h160 = self.RIPEMD160_SHA256(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58(prefix + h160 + hash256(prefix + h160)[0:4])
        # (version + hashed public key + checksum) encoded in base58

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
    
    def sign(self, z):
        k = random.randint(0, N)
        r = (k * G).x.num
        k_inv = pow(k, N-2, N)
        s = (k_inv * (z + self.secret * r)) % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)
    
    def WIF(self, compressed = True, testnet = False):
        secret_bytes = self.secret.to_bytes(32, 'big')
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        
        return encode_base58(prefix + secret_bytes + suffix + hash256(prefix + secret_bytes + suffix)[0:4])
        # (prefix + secret + suffix + checksum) encodeed in base58

def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def encode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''

    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def RIPEMD160_SHA256(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()




if __name__ == '__main__':
    e1 = int.from_bytes(hash256(b'Jimmy secret'), 'big')
    e2 = int.from_bytes(hash256(b'nsysu bitcoin secret'), 'big')
    private_key1 = PrivateKey(e1)
    private_key2 = PrivateKey(e2)
    print("address (e=23396051, uncompressed SEC, testnet): ", private_key1.point.address(compressed = False, testnet = True))
    print("address (e=23396052, compressed SEC, testnet): ", private_key2.point.address(compressed = True, testnet = True))