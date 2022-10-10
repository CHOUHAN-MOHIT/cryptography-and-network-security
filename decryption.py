# Decryption utilities for Simplified IDEA

# this will arrange the key in the order that they are required for the decryption procces
def arrange(subkey):
    k11 = subkey[24]
    k12 = subkey[25]
    k13 = subkey[26]
    k14 = subkey[27]
    k15 = subkey[22]
    k16 = subkey[23]
    k21 = subkey[18]
    k22 = subkey[19]
    k23 = subkey[20]
    k24 = subkey[21]
    k25 = subkey[16]
    k26 = subkey[17]
    k31 = subkey[12]
    k32 = subkey[13]
    k33 = subkey[14]
    k34 = subkey[15]
    k35 = subkey[10]
    k36 = subkey[11]
    k41 = subkey[6]
    k42 = subkey[7]
    k43 = subkey[8]
    k44 = subkey[9]
    k45 = subkey[4]
    k46 = subkey[5]
    k51 = subkey[0]
    k52 = subkey[1]
    k53 = subkey[2]
    k54 = subkey[3]

    arr =[k11,k12,k13,k14,k15,k16,k21,k22,k23,k24,k25,k26,k31,k32,k33,k34,k35,k36,k41,k42,k43,k44,k45,k46,k51,k52,k53,k54]
    return arr

#this will generate the inverses for every key according to their operation
def getInvrs(subkey , opreation):
    add_invs = {
                '0000':'0000','0001':'1111','0010':'1110','0011':'1101',
                '0100':'1100','0101':'1011','0110':'1010','0111':'1001',
                '1000':'1000','1001':'0111','1010':'0110','1011':'0101',
                '1100':'0100','1101':'0011','1110':'0010','1111':'0001'
            }
    mul_invs = {
                '0000':'0000', '0001':'0001','0010':'1001','0011':'1010',
                '0100':'1101','0101':'0111','0110':'0011','0111':'0101',
                '1000':'1111','1001':'1001','1010':'1100','1011':'1110',
                '1100':'1010','1101':'0100','1110':'1011','1111':'1000'
            }
    if opreation =='*' :
        return mul_invs[subkey]
    else:
        return add_invs[subkey]

# this will generate keys for all encryption rounds
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
    inverseSUbkeys = []
    subkeys = subkeys + nibbles1
    subkeys = subkeys + nibbles2
    subkeys = subkeys + nibbles3
    subkeys = subkeys + nibbles4

    return arrange(subkeys)

# this is to perform 14 steps of one round  
def round(round_no , PT_nibbles , keys):
    round_no = round_no - 1
    # 1. Multiply X1 and the first subkey Z1.
    x1 = 16 if int(PT_nibbles[0] , 2) == 0 else int(PT_nibbles[0] , 2)
    k1 = 16 if int(getInvrs(keys[(6*round_no) + 0] , '*') , 2) == 0 else int(getInvrs(keys[(6*round_no) + 0] , '*') , 2)
    r1 = x1 * k1
    r1 =  0 if r1 == 16 else r1 % 17
    r1 =  0 if r1 == 16 else r1

    # 2. Add X2 and the second subkey Z2.
    r2 = int(PT_nibbles[1] , 2) + int(getInvrs(keys[(6*round_no) + 1], '+') , 2)
    r2 = r2 % 16

    # 3. Add X3 and the third subkey Z3.
    r3 = int(PT_nibbles[2] , 2) + int(getInvrs(keys[(6*round_no) + 2], '+') , 2)
    r3 = r3 % 16

    # 4. Multiply X4 and the fourth subkey Z4.
    x4 = 16 if int(PT_nibbles[3] , 2) == 0 else int(PT_nibbles[3] , 2)
    k4 = 16 if int(getInvrs(keys[(6*round_no) + 3] , '*'), 2) == 0 else int(getInvrs(keys[(6*round_no) + 3], '*') , 2)
    r4 = x4 * k4
    r4 = 0 if r4 == 16 else r4 % 17
    r4 = 0 if r4 == 16 else r4

    # 5. Bitwise XOR the results of steps 1 and 3.
    r5 = r1 ^ r3

    # 6. Bitwise XOR the results of steps 2 and 4.
    r6 = r2 ^ r4

    # 7. Multiply the result of step 5 and the fifth subkey Z5.
    r5 = 16 if r5 == 0 else r5
    k5 = 16 if int(getInvrs(keys[(6*round_no) + 4], '*') , 2) == 0 else int(getInvrs(keys[(6*round_no) + 4], '*' ), 2)
    r7 = r5 * int(keys[(6*round_no) + 4],2)
    r7 = 0 if r7 == 16 else r7 % 17
    r7 = 0 if r7 == 16 else r7

    # 8. Add the results of steps 6 and 7.
    r8 = r6 + r7
    r8 = r8 % 16

    # 9. Multiply the result of step 8 and the sixth subkey Z6.
    r8 = 16 if r8 == 0 else r8
    k6 = 16 if int(getInvrs(keys[(6*round_no) + 5] , '*') , 2) == 0 else int(getInvrs(keys[(6*round_no) + 5] , '*') , 2)
    r9 = r8 * int(keys[(6*round_no) + 5] , 2)
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

# this is the final round(half round)
def finalrounds(PT_nibbles , keys):
    round_no = 4
    # 1. Multiply X1 and the first subkey Z1.
    x1 = 16 if int(PT_nibbles[0] , 2) == 0 else int(PT_nibbles[0] , 2)
    k1 = 16 if int(getInvrs(keys[(6*round_no) + 0] , '*') , 2) == 0 else int(getInvrs(keys[(6*round_no) + 0] , '*') , 2)
    r1 = x1 * k1
    r1 =  0 if r1 == 16 else r1 % 17
    r1 =  0 if r1 == 16 else r1 

    # 2. Add X2 and the second subkey Z2.
    r2 = int(PT_nibbles[1] , 2) + int(getInvrs(keys[(6*round_no) + 1], '+') , 2)
    r2 = r2 % 16

    # 3. Add X3 and the third subkey Z3.
    r3 = int(PT_nibbles[2] , 2) + int(getInvrs(keys[(6*round_no) + 2], '+') , 2)
    r3 = r3 % 16

    # 4. Multiply X4 and the fourth subkey Z4.
    x4 = 16 if int(PT_nibbles[3] , 2) == 0 else int(PT_nibbles[3] , 2)
    k4 = 16 if int(getInvrs(keys[(6*round_no) + 3] , '*'), 2) == 0 else int(getInvrs(keys[(6*round_no) + 3], '*') , 2)
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
            k = '0' + k

    result = ''
    result = result + nibs[3] + nibs[2] + nibs[1] + nibs[0]
    return result

# the decryption funtion for Simplified IDEA
def decryption(PT , Key):
    # dividing the Plaintext into nibbles
    nibbles =  [PT[i:i+4] for i in range(0, len(PT) - 3, 4)]

    # generating subkeys for encryption rounds
    subkeys = keygenerator(Key)
    
    # performing encrytion rounds
    nib1 = round(1 , nibbles, subkeys)
    nib2 = round(2 , nib1 , subkeys)
    nib3 = round(3 , nib2 , subkeys)
    nib4 = round(4 , nib3 , subkeys)

    cipher_nibbles = finalrounds(nib4 , subkeys)

    return bToS(cipher_nibbles)
