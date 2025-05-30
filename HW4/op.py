import hashlib
from Address_and_WIF import * 


def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def hash160(s):
    return hashlib.new("ripemd160", hashlib.sha256(s).digest()).digest()

def little_endian_to_int(b):
    return int.from_bytes(b, byteorder = 'little')

def int_to_little_endian(i, length):
    return i.to_bytes(length, byteorder = 'little')

def op_dup(stack):
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True

def op_hash256(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True

def op_ripemd160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.new("ripemd160", element).digest())
    return True

def op_hash160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    h160 = hash160(element)
    stack.append(h160)
    return True



def op_checksig(stack, z):
    if len(stack) < 2:
        return False
    pubkey_sec = stack.pop()
    sig_der = stack.pop()
    pubkey = S256Point.parse(sec_bin=pubkey_sec)
    sig = Signature.parse(sig_der)
    stack.append(encode_num(pubkey.verify(z, sig)))
    return True

def OP_IF(stack, cmds):
    pass

def OP_NOTIF(stack, cmds):
    pass

def op_6(stack):
    stack.append(encode_num(6))
    return True

def op_2(stack):
    stack.append(encode_num(2))
    return True

def op_equal(stack):
    if len(stack) < 2:
        return False
    a = stack.pop()
    b = stack.pop()
    stack.append(encode_num(a == b))
    return True

def op_add(stack):
    if len(stack) < 2:
        return False
    a = decode_num(stack.pop())
    b = decode_num(stack.pop())
    stack.append(encode_num(a + b))
    return True

def op_mul(stack):
    if len(stack) < 2:
        return False
    a = decode_num(stack.pop())
    b = decode_num(stack.pop())
    stack.append(encode_num(a * b))
    return True

def encode_num(num):
    if num == 0:
        return b''
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num: # convert number to little endian
        result.append(abs_num & 0xff)
        abs_num >>= 8
    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)
    
def decode_num(element):
    if element == b'':
        return 0
    big_endian = element[::-1]
    if big_endian[0] == 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]: # byte 0已經放入，現在只要在放1之後的byte
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result
    
def op_0(stack):
    stack.append(encode_num(0))
    return True


# OP_TOALTSTACK, OP_FROMALTSTACK
# OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
    
OP_CODE_FUNCTIONS = {
    82: op_2,
    86: op_6,
    118: op_dup,
    135: op_equal,
    147: op_add,
    149: op_mul,
    166: op_ripemd160,
    169: op_hash160,    
    170: op_hash256,
    172: op_checksig
}

OP_CODE_NAMES = {
    82: "OP_2",
    86: "OP_6",
    118: "OP_DUP",
    135: "OP_EQUAL",
    136: "OP_EQUALVERIFY",
    147: "OP_ADD",
    149: "OP_MUL",
    166: "OP_RIPEMD160",
    169: "OP_HASH160",
    170: "OP_HASH256",
    172: "OP_CHECKSIG"
}