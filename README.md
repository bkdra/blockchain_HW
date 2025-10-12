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
