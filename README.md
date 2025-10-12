> You can see details of HW from each folder
# HW1
## explanation
1st and 2nd part
: Use Python to build finite field calculation including add, substrate, multiply, divide and power 

3rd and 4th part
: Compute the slope and sum of the points on the Elliptic Curve in finite field

## How to execute
for 1st and 2nd part
> python HW1/FiniteField.py

for 3rd and 4th part
> python HW1/EllipticCurves.py

# HW2
## explanation
1st part
: Check whether the given signature is valid

2nd part
: Sign the message with the given private key

3rd part
: Find the uncompressed/compressed SEC format of the public key by the given private key, and find the DER format for a signature

4th part
: Find the address of a transaction corresponding to Public Keys whose Private Key secrets are given, and find the WIF for a given private key.

## How to execute
for 1st part
> python HW2/Verify.py

for 2nd part
> python HW2/Sign.py

for 3rd part
> python HW2/serialization.py

for 4th part
> python HW2/Address_and_WIF.py

# HW3
## explanation
1st part
: Find the ScriptSig of the transaction's input and ScriptPubKey of the transaction's output from a given hex transaction.

2nd part
: Implement op_checksig, which is a function of BitCoin Script to check whether the public key and signature on the stack are valid.

3rd part
: There is a ScriptPubKey:
  *	767695935687 
    *	script_pubkey = Script([0x76, 0x76, 0x95, 0x93, 0x56, 0x87]) 
  *	56 = OP_6 
  *	76 = OP_DUP 
  *	87 = OP_EQUAL 
  * 93 = OP_ADD 
  * 95 = OP_MUL

  We have to create a ScriptSig that can unlock this ScriptPubKey
  (I use ScriptSig:[0x52], which is a command with solely a OP_2)

## How to execute
for all three parts:
> python HW3/transaction.py

# HW4
## explanation
1st part
: Create your own testnet4 transaction and process its input, output about payment + change and validation, get some coins for yourself from a fauset and send them back. This transaction have to be broadcast to testnet4

2nd part
: Implement op_checkmultisig, which is a function of BitCoin Script to check whether the multiple public keys and signatures on the stack are valid.

3rd part
: Validate whether the second signature from the transaction as follows is valid.
> hex_tx = '0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000'

 this transaction is signed with p2sh (has RedeemScript)

 ## How to execute
 for 1st part (see HW4_report to get more detail about the step of building a transaction)
> python HW4/p1.py

for 2nd part
> python HW4/p2.py

for 3rd part
> python HW4/p3.py
