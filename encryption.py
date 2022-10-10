# Decryption utilities for Simplified idea

# this will generate the keys for encryption rounds
def keygenerator(Key):
    # shiffting the key for subkey generation 
    key2 = Key[6:]+Key[0:6]
    key3 = key2[6:]+key2[0:6]
    key4 = key3[6:]+key3[0:6]

    # splitting the keys into nibbles 
    nibbles1 =  [Key[i:i+4] for i in range(0, len(Key) - 3, 4)]
    nibbles2 =  [key2[i:i+4] for i in range(0, len(key2) - 3, 4)]
    nibbles3 =  [key3[i:i+4] for i in range(0, len(key3) - 3, 4)]
    nibbles4 =  [key4[i:i+4] for i in range(0, len(key4) - 3, 4)]

    # concatinating the all subkeys to a single list
    subkeys = []
    subkeys = subkeys + nibbles1
    subkeys = subkeys + nibbles2
    subkeys = subkeys + nibbles3
    subkeys = subkeys + nibbles4

    return subkeys

# a round consisting of 14 steps 
def round(round_no , PT_nibbles , keys):
    round_no = round_no - 1
    # 1. Multiply X1 and the first subkey Z1.
    x1 = 16 if int(PT_nibbles[0] , 2) == 0 else int(PT_nibbles[0] , 2)
    k1 = 16 if int(keys[(6*round_no) + 0] , 2) == 0 else int(keys[(6*round_no) + 0] , 2)
    r1 = x1 * k1
    r1 =  0 if r1 == 16 else r1 % 17
    r1 =  0 if r1 == 16 else r1 

    # 2. Add X2 and the second subkey Z2.
    r2 = int(PT_nibbles[1] , 2) + int(keys[(6*round_no) + 1] , 2)
    r2 = r2 % 16

    # 3. Add X3 and the third subkey Z3.
    r3 = int(PT_nibbles[2] , 2) + int(keys[(6*round_no) + 2] , 2)
    r3 = r3 % 16

    # 4. Multiply X4 and the fourth subkey Z4.
    x4 = 16 if int(PT_nibbles[3] , 2) == 0 else int(PT_nibbles[3] , 2)
    k4 = 16 if int(keys[(6*round_no) + 3] , 2) == 0 else int(keys[(6*round_no) + 3] , 2)
    r4 = x4 * k4
    r4 = 0 if r4 == 16 else r4 % 17
    r4 = 0 if r4 == 16 else r4

    # 5. Bitwise XOR the results of steps 1 and 3.
    r5 = r1 ^ r3

    # 6. Bitwise XOR the results of steps 2 and 4.
    r6 = r2 ^ r4

    # 7. Multiply the result of step 5 and the fifth subkey Z5.
    r5 = 16 if r5 == 0 else r5
    k5 = 16 if int(keys[(6*round_no) + 4] , 2) == 0 else int(keys[(6*round_no) + 4] , 2)
    r7 = r5 * k5
    r7 = 0 if r7 == 16 else r7 % 17
    r7 = 0 if r7 == 16 else r7 

    # 8. Add the results of steps 6 and 7.
    r8 = r6 + r7
    r8 = r8 % 16

    # 9. Multiply the result of step 8 and the sixth subkey Z6.
    r8 = 16 if r8 == 0 else r8
    k6 = 16 if int(keys[(6*round_no) + 5] , 2) == 0 else int(keys[(6*round_no) + 5] , 2)
    r9 = r8 * k6
    r9 = 0 if r9 == 16 else r9 % 17
    r9 = 0 if r9 == 16 else r9

    # 10. Add the results of steps 7 and 9.
    r10 = r7 + r9
    r10 = r10 % 16

    # 11. Bitwise XOR the results of steps 1 and 9.
    r11 = r9 ^ r1

    # 12. Bitwise XOR the results of steps 3 and 9.
    r12 = r3 ^ r9

    # 13. Bitwise XOR the results of steps 2 and 10.
    r13 = r2 ^ r10

    # 14. Bitwise XOR the results of steps 4 and 10.    
    r14 = r4 ^ r10

    print("Round %s Cipher text:" %(round_no+1),bToS([bin(r1) , bin(r2) , bin(r3) , bin(r4)]))
    return [bin(r11) , bin(r13) , bin(r12) , bin(r14)]
# final round(half round)
def finalrounds(PT_nibbles , keys):
    round_no = 4
    # 1. Multiply X1 and the first subkey Z1.
    x1 = 16 if int(PT_nibbles[0] , 2) == 0 else int(PT_nibbles[0] , 2)
    k1 = 16 if int(keys[(6*round_no) + 0] , 2) == 0 else int(keys[(6*round_no) + 0] , 2)
    r1 = x1 * k1
    r1 =  0 if r1 == 16 else r1 % 17
    # 2. Add X2 and the second subkey Z2.
    r2 = int(PT_nibbles[1] , 2) + int(keys[(6*round_no) + 1] , 2)
    r2 = r2 % 16
    # 3. Add X3 and the third subkey Z3.
    r3 = int(PT_nibbles[2] , 2) + int(keys[(6*round_no) + 2] , 2)
    r3 = r3 % 16
    # 4. Multiply X4 and the fourth subkey Z4.
    x4 = 16 if int(PT_nibbles[3] , 2) == 0 else int(PT_nibbles[3] , 2)
    k4 = 16 if int(keys[(6*round_no) + 3] , 2) == 0 else int(keys[(6*round_no) + 3] , 2)
    r4 = x4 * k4
    r4 = 0 if r4 == 16 else r4 % 17
    r4 = 0 if r4 == 16 else r4

    print("Round %s Cipher text:" %(round_no+1),bToS([bin(r1) , bin(r2) , bin(r3) , bin(r4)]))
    return [bin(r1) , bin(r2) , bin(r3) , bin(r4)]

# this is to convert from binary list to string
def bToS(bins):
    nibs = []

    for k in bins:
        k = k[2:]
        while len(k) <= 4:
            if len(k) == 4:
                nibs.insert(0 , k)
            #print(len(k))
            k = '0' + k

    result = ''
    result = result + nibs[3] + nibs[2] + nibs[1] + nibs[0]
    return result

# the encryption function for simplified IDEA
def encryption(PT , Key):
    # dividing the Plaintext into nibbles
    nibbles =  [PT[i:i+4] for i in range(0, len(PT) - 3, 4)]

    # generating subkeys for encryption rounds
    subkeys = keygenerator(Key)
    
    # performing encrytion rounds
    nib1 = round(1 , nibbles, subkeys)
    nib2 = round(2 , nib1 , subkeys)
    nib3 = round(3 , nib2 , subkeys)
    nib4 = round(4 , nib3 , subkeys)
    # final round
    cipher_nibbles = finalrounds(nib4 , subkeys)

    return bToS(cipher_nibbles)
