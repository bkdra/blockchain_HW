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
    sig = Signature.parse(sig_der[:-1])  # Remove the SIGHASH_ALL byte at the end
    stack.append(encode_num(pubkey.verify(z, sig)))
    return True

def op_checkmultisig(stack, z):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        der_signatures.append(stack.pop()[:-1])  # Each DER signature is assumed to be signed with SIGHASH_ALL 
    stack.pop()  # Take care of the off-by-one error by consuming the only remaining element of the stack and not doing anything with the element
    try:
        for i in range(len(sec_pubkeys)):
            print("pubkey:", sec_pubkeys[i].hex())
            sec_pubkeys[i] = S256Point.parse(sec_bin=sec_pubkeys[i])
        for i in range(len(der_signatures)):
            print("signature:", der_signatures[i].hex())
            der_signatures[i] = Signature.parse(der_signatures[i])
        
        
        pubkey_index = 0
        for i in range(m):
            while pubkey_index < len(sec_pubkeys) and not sec_pubkeys[pubkey_index].verify(z, der_signatures[i]):
                pubkey_index += 1
            if pubkey_index == len(sec_pubkeys):
                return False
            pubkey_index += 1
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True


def OP_IF(stack, cmds):
    pass

def OP_NOTIF(stack, cmds):
    pass

def op_6(stack):
    stack.append(encode_num(6))
    return True

def op_1(stack):
    stack.append(encode_num(1))
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

def op_equalverify(stack):
    if len(stack) < 2:
        return False
    a = stack.pop()
    b = stack.pop()
    if a == b:
        return True
    else:
        return False  

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
    0: op_0,
    81: op_1,
    82: op_2,
    86: op_6,
    118: op_dup,
    135: op_equal,
    136: op_equalverify,
    147: op_add,
    149: op_mul,
    166: op_ripemd160,
    169: op_hash160,    
    170: op_hash256,
    172: op_checksig,
    174: op_checkmultisig
}

OP_CODE_NAMES = {
    0: "OP_0",
    81: "OP_1",
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
    172: "OP_CHECKSIG",
    174: "OP_CHECKMULTISIG"
}