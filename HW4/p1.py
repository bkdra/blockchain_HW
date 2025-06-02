from Address_and_WIF import *
from EllipticCurves import *
from op import *
from FiniteField import *
from transaction import *

prev_tx = "e344dd0ff84e89d340c640e3e309f6cf478f4d2ec12d8297deee986210393a90"
prev_index = 0
tx_in = TxIn(prev_tx=bytes.fromhex(prev_tx), prev_index=prev_index)

tx_outs  = []
change_amount = int(0.0024 * 100000000)
change_h160 = decode_base58("mpdZVtnA4sh4bHRLLDv2SvWCStc8HSa3C8")
change_script = p2pkh_script(change_h160)
change_output = TxOut(amount=change_amount, script_pubkey=change_script)

target_amount = int(0.0025 * 100000000)
target_160 = decode_base58("mhi79YboWzkep1KWrFmCNBVcaLSyXwszba")
target_script = p2pkh_script(target_160)
target_output = TxOut(amount=target_amount, script_pubkey=target_script)

tx_obj = Tx(2, [tx_in], [change_output, target_output], 0, True)

z = tx_obj.sig_hash(0)

raw_private_key = 18676381219334607853775185658063683742347947593352056678331552827194409684045
private_key = PrivateKey(secret=raw_private_key)
der = private_key.sign(z).DER()
sig = der + int(1).to_bytes(1, 'big')
sec = private_key.point.sec()
script_sig = Script([sig, sec])
tx_obj.tx_ins[0].script_sig = script_sig


print(tx_obj)
print()
if tx_obj.verify():
    print("This transaction is OK")
else:
    print("This transaction is not OK")
print()
print("Transaction Hex:")
print(tx_obj.serialize().hex())