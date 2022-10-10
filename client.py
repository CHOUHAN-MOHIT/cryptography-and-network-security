import socket
from encryption import *
from decryption import *
from elgamal import *


def ToString(c2 , c1):
    msg = ""

    for s in c2:
        msg = msg + str(s) + ','
    
    msg = msg + ',' + str(c1)
    return msg

# creating elgamal keys
prime = random.randint(pow(10, 20), pow(10, 50))
e1 = random.randint(2, prime)
# Private key for receiver
d = gen_key(prime)
# print("private key:\n" , d)
e2 = power(e1, d, prime)

# Create a socket object
s = socket.socket()        
 
# Define the port
port = 12345               
 
# connect to the server on local computer
s.connect(('127.0.0.1', port))
 
# welcome message
print (s.recv(1024).decode())

# requesting for public key
s.send("{+} Please send the Public key.".encode())

# getting public key
public_key = s.recv(1024).decode()
public_key = public_key.split(",")

Pt = input("Enter the Message(16-bit): ")
secret_key = input("Enter the Secret key(16-bit):")
c2 , c1 = encrypt(secret_key ,int(public_key[0]), int(public_key[1]) , int(public_key[2]))
print("NOTE: Parameters for Elgamal Key generation are generated randomly.")
print("->Server Public key(p , e1 , e2)")
print("\tp:", prime)
print("\te1:", e1)
print("\te2:", e2)

en_secret_key = ToString(c2 , c1)
print("Encrypted secret key:" , en_secret_key)
s.send(en_secret_key.encode())

# padding the secret_key to make it 32-bit
secret_key = secret_key + '0011111101011001'

ciphertext = encryption(Pt , secret_key)
print("cipher text:" , ciphertext)
s.send(ciphertext.encode())
# print("you got it :", en_secret_key)

# close the connection
s.close()  
