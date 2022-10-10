# Utility function for ElGamal Encryption and Decryption

import random
from math import pow

# To find the gcd using euclidian algorithm
def gcd(a, b):
	if a < b:
		return gcd(b, a)
	elif a % b == 0:
		return b;
	else:
		return gcd(b, a % b)

# Generating large random numbers
def gen_key(q):

	key = random.randint(pow(10, 20), q)
	while gcd(q, key) != 1:
		key = random.randint(pow(10, 20), q)

	return key

# Modular exponentiation
def power(a, b, n):
	x = 1
	y = a

	while b > 0:
		if b % 2 != 0:
			x = (x * y) % n
		y = (y * y) % n
		b = int(b / 2)

	return x % n


# Asymmetric Elgamal encryption
def encrypt(msg, prime, e2, e1):

	en_msg = []

	r = gen_key(prime)# Private key for sender
	e2r = power(e2, r, prime)
	c1 = power(e1, r, prime)
	
	for i in range(0, len(msg)):
		en_msg.append(msg[i])

	# print("c1 used  : ", c1)
	# print("e1^r used : ", e2r)
	for i in range(0, len(en_msg)):
		en_msg[i] = e2r * ord(en_msg[i]) # c2

	# return listToString(en_msg)+ "," + str(c1)
	return en_msg , c1

# Asymmetric Elgamal decryption
def decrypt(en_msg, c1, d, prime):

	d_msg = []
	c1d = power(c1, d, prime)
	# print(c1d)
	for i in range(0, len(en_msg)):
		d_msg.append(chr(int(en_msg[i]/c1d)))
		
	return d_msg

# Elgamal key generation
def generate_keys():
	
	prime = random.randint(pow(10, 20), pow(10, 50))
	e1 = random.randint(2, prime)

	d = gen_key(prime) # Private key for receiver
	e2 = power(e1, d, prime)

	return [prime , e2 , e1] , d

