from Address_and_WIF import *
from EllipticCurves import *
from op import *
from FiniteField import *
from transaction import *

der1 = "3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a89937"
der1_hash = "3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701"
der2 = "3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e754022"
der2_hash = "3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201"
sec1 = "022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70"
sec2 = "03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71"

hex_redeem_script_2_of_2 = '475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
hex_tx = '0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000'
hex_redeem_script_1_of_2 = '475121022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
stream = BytesIO(bytes.fromhex(hex_tx))
redeem_script_2_of_2 = Script.parse(BytesIO(bytes.fromhex(hex_redeem_script_2_of_2)))
tx = Tx.parse(stream)
s = int_to_little_endian(tx.version, 4)
s += encode_varint(len(tx.tx_ins))
s += TxIn(prev_tx=tx.tx_ins[0].prev_tx, 
          prev_index=tx.tx_ins[0].prev_index,
          script_sig = redeem_script_2_of_2, 
          sequence=tx.tx_ins[0].sequence).serialize()
s += encode_varint(len(tx.tx_outs))
for tx_out in tx.tx_outs:
    s += tx_out.serialize()
s += int_to_little_endian(tx.locktime, 4)
s += int_to_little_endian(1, 4)
z = int.from_bytes(hash256(s), 'big')

redeem_script_1_of_2 = Script.parse(BytesIO(bytes.fromhex(hex_redeem_script_1_of_2)))
der1_b = bytes.fromhex(der1)
der2_b = bytes.fromhex(der2)
der1_hash_b = bytes.fromhex(der1_hash)
der2_hash_b = bytes.fromhex(der2_hash)
sec1 = bytes.fromhex(sec1)
sec2 = bytes.fromhex(sec2)
sig1 = Signature.parse(der1_b)
sig2 = Signature.parse(der2_b)
pubkey1 = S256Point.parse(sec_bin=sec1)
pubkey2 = S256Point.parse(sec_bin=sec2)

script_pubkey = redeem_script_1_of_2
script_sig = Script([0, der2_hash_b])
combined_script = script_sig + script_pubkey
print("1-of-2 multisig is valid? :", combined_script.evaluate(z))
print()
script_sig = Script([0, der1_hash_b, der2_hash_b])
script_pubkey = redeem_script_2_of_2
combined_script = script_sig + script_pubkey
print("2-of-2 multisig is valid? :", combined_script.evaluate(z))