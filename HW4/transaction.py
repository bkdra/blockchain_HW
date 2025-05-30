from Address_and_WIF import *
from io import BytesIO
from op import *
from blockstream import *

SIGHASH_ALL = 1

def little_endian_to_int(b):
    return int.from_bytes(b, byteorder = 'little')

def int_to_little_endian(i, length):
    return i.to_bytes(length, byteorder = 'little')

def read_varint(s):
    i = s.read(1)
    i = i[0]  # convert bytes to int
    if i == 0xfd:
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        return little_endian_to_int(s.read(8))
    else:
        return i

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        return ValueError(f"Integer too large: {i}")

def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.index(c)
    combined = num.to_bytes(25, byteorder='big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError("bad address: {} {}".format(checksum, hash256(combined[:-4])[:4]))
    return combined[1:-4]

def p2pkh_script(h160):
    return Script([0x76, 0xa9, 0x14, h160, 0x88, 0xac])

class Tx:
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet = False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
    
    def id(self):
        return hash256(self.serialize())[::-1].hex()
    
    # return a transaction object according to the serialization
    @classmethod
    def parse(cls, serialization, testnet = False):
        version = little_endian_to_int(serialization.read(4))
        num_inputs = read_varint(serialization)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(serialization))
        num_outputs = read_varint(serialization)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(serialization))
        locktime = little_endian_to_int(serialization.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet)
    
    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result
    
    def fee(self, testnet = False):
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(testnet=testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum
    
    def sig_hash(self, input_index, redeem_script = None):
        s = int_to_little_endian(self.version, 4)
        s += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                if redeem_script:
                    script_sig = redeem_script
                else:
                    script_sig = tx_in.script_pubkey(self.testnet)
            else:
                script_sig = None
            s += TxIn(prev_tx=tx_in.prev_tx,
                          prev_index=tx_in.prev_index,
                          script_sig= script_sig,
                          sequence=tx_in.sequence
                ).serialize()
        s += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(1, 4)
        h256 = hash256(s)
        return int.from_bytes(h256, byteorder='big')
    
    def verify_input(self, input_index):
        tx_in = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey(self.testnet)
        if script_pubkey.is_p2sh_script_pubkey():
            cmd = tx_in.script_sig.cmds[-1]
            raw_redeem = encode_varint(len(cmd)) + cmd
            redeem_script = Script.parse(BytesIO(raw_redeem))
        else:
            redeem_script = None
        z = self.sig_hash(input_index, redeem_script=redeem_script)
        combined_script = tx_in.script_sig + script_pubkey
        return combined_script.evaluate(z)
    
    def verify(self):
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True
    
    def sign_input(self, input_index, private_key):
        z = self.sig_hash(input_index)
        der = private_key.sign(z).DER()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        sec = private_key.point.sec()
        self.tx_ins[input_index].script_sig = Script([sig, sec])
        return self.verify_input(input_index)
    
class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig = None, sequence = 0xffffffff):
        self.prev_tx = prev_tx # 32bytes byte string. last UTXO ID(result of hash256 of the previous transaction's serialization)
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    # return a transaction input object according to the serialization
    @classmethod
    def parse(cls, s):
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)
    
    def serialize(self):
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result
    
    def fetch_tx(self, testnet = False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)
    
    def value(self, testnet = False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount
    
    def script_pubkey(self, testnet = False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey
        


class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey
    @classmethod
    def parse(cls, s):
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)
    
    def serialize(self):
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result

class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet = False):
        if testnet:
            return f'https://blockchain.info/testnet/api'
        else:
            return f'https://blockchain.info/api'
    
    @classmethod
    def fetch(cls, tx_id, testnet = False, fresh = False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}/hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
        
            if tx.id() != tx_id:
                raise ValueError("not the same id: {} vs {}".format(tx.id(), tx_id))
            
            cls.cache[tx_id] = tx
        
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    
     

class Script:
    def __init__(self, cmds = None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds
    
    def __add__(self, other):
        return Script(self.cmds + other.cmds)
    
    @classmethod
    def parse(cls, s):
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1) # read a byte means next command
            count += 1
            current_byte = current[0] # from bytes to int
            if current_byte >= 1 and current_byte <= 75: # means the length of the next command
                n = current_byte
                cmds.append(s.read(n))
                count += n
            elif current_byte == 76: # OP_PUSHDATA1, next byte is the length of the next command
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77: # OP_PUSHDATA2, next two bytes are the length of the next command
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                cmds.append(current_byte)
        if count != length:
            raise ValueError("parsing script failed")
        return cls(cmds)

    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int: # -> cmd is a opcode
                result += int_to_little_endian(cmd, 1)
            else: # cmd is a byte string => element
                length = len(cmd) # 下面這些if在把command的長度放入
                if length <= 75:
                    result += int_to_little_endian(length, 1)
                elif length < 0x100:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length <= 520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long a cmd')
                result += cmd
        return result
    
    def serialize(self):
        result = self.raw_serialize()
        total_len = len(result)
        return encode_varint(total_len) + result
    
    def is_p2sh_script_pubkey(self):
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9\
                    and type(self.cmds[1])  == bytes and len(self.cmds[1]) == 20\
                    and self.cmds[2] == 0x87
    
    def evaluate(self, z):
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100): # OP_IF, OP_NOTIF
                    if not operation(stack, cmds):
                        print(f"Operation {OP_CODE_NAMES[cmd]} failed")
                        return False
                elif cmd in (107, 108): # OP_TOALTSTACK, OP_FROMALTSTACK
                    if not operation(stack, altstack):
                        print(f"Operation {OP_CODE_NAMES[cmd]} failed")
                        return False
                elif cmd in (172, 173, 174, 175): # OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
                    if not operation(stack, z):
                        print(f"Operation {OP_CODE_NAMES[cmd]} failed")
                        return False
                else:
                    if not operation(stack):
                        print(f"Operation {OP_CODE_NAMES[cmd]} failed")
                        return False
            else: # not a opcode, it's an element(e.g. signature, pubkey)
                stack.append(cmd)
                if len(cmds) == 3 and cmds[0] == 0xa9\
                    and type(cmds[1])  == bytes and len(cmds[1]) == 20\
                    and cmds[2] == 0x87:
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()

                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    if not op_verify(stack):
                        return False
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)
                    
        if len(stack) == 0:
            print("run length is 0")
            return False
        if stack.pop() == b'': # last element is empty, means the script is not valid
            print("run empty element")
            return False
        return True

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    
if __name__ == '__main__':
    # 1
    hex_transaction = "010000000117e18a4a4a0af876b1b0a4764ee77c74106e07667dd94c4d61271f3d356cbf62000000006b4830450221009e661e94622a66f6c65f270d859828360c825ee755d675c9cbb2214685ba08fc022005aa4abaf21a84519f0c8ff40c633a0e4a624c639d25c0ea908d0d5e463749a80121036ddc934a5fbd5222ead406a4334462aaa62f83d0b02255c0a582f9038a17bbfdffffffff02cc162c00000000001976a914051b07716871833694a762ad15565b86da46622488ac16ae0e00000000001976a914c03ee4258550c77bcf61829c7cb636cd521ebfc588ac00000000"
    stream = BytesIO(bytes.fromhex(hex_transaction))
    tx_obj = Tx.parse(stream)
    print("Q1: ")
    print("1st input script_sig: ", tx_obj.tx_ins[0].script_sig)
    print("1st output script_pubkey: ", tx_obj.tx_outs[0].script_pubkey)
    print("2nd output amount: ", tx_obj.tx_outs[1].amount)
    print()
    # 2
    print("Q2: ")
    P = S256Point(0x801be5a7c4faf73dd1c3f28cebf78d6ba7885ead88879b76ffb815d59056af14,
                   0x826ddfcc38dafe6b8d463b609facc009083c8173e21c5fc45b3424964e85f49e)
    z = 0x90d7aecf3f2855d60026f10faab852562c76e7e043cf243474ba5018447c2c22
    r = 0xf01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f
    s = 0x22afcd685b7c0c8b525c2a52529423fcdff22f69f3e9c175ac9cb3ec08de87d8
    sig = Signature(r, s)
    pubkey_sec = P.sec()
    sig_der = sig.DER()
    script_pubkey = Script([pubkey_sec, 0xac])
    script_sig = Script([sig_der])
    combined_script = script_sig + script_pubkey
    print("combined script: ", combined_script)
    print("evaluate result: ", combined_script.evaluate(z))
    print()


    # 3
    print("Q3: ")
    script_pubkey = Script([0x76, 0x76, 0x95, 0x93, 0x56, 0x87])
    script_sig = Script([0x52])
    combined_script = script_sig+script_pubkey 
    print("combined script: ", combined_script)
    print("evaluate result: ", combined_script.evaluate(0))