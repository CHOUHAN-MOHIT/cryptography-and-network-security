import socket
from encryption import *
from decryption import *
from elgamal import *		

# this will format the recieved cipher to desired format for futher processing
def format_cipher(key_cipher):
    key_cipher = key_cipher.split(",")

    c2 = []

    l = len(key_cipher)

    for i in range (0 , l-2):
        c2.append(int(key_cipher[i]))
    
    c1 = int(key_cipher[l-1])
    return c2 , c1

    

# next create a socket object
s = socket.socket()		
print ("[+] Socket successfully created.")

# bind the port to the address
s.bind(('', 12345))		
print ("[+] Socket binded to %s." %(12345))

# put the socket into listening mode
s.listen(5)	
print ("[+] Socket is ready to listen.")

# creating elgamal keys
prime = random.randint(pow(10, 20), pow(10, 50))
e1 = random.randint(2, prime)
# Private key for receiver
d = gen_key(prime)
# print("private key:\n" , d)
e2 = power(e1, d, prime)

print("NOTE: Parameters for Elgamal Key generation are generated randomly.")
print("-Server Public key(p , e1 , e2):")
print("\tp:", prime)
print("\te1:", e1)
print("\te2:", e2)

# concatinating as string to send to client
public_key = str(prime) + ',' + str(e2) +  ',' + str(e1)

while True:

    print("\n[+] Waiting for connection...\n")
    # Establish connection with client.
    c, addr = s.accept()	
    print ('[+] Got connection from', addr  , '.\n')

    # send a thank you message to the client. encoding to send byte type.
    c.send('[+] You are connected to the Server.'.encode())

    print(c.recv(1024).decode())

    c.send(public_key.encode())

    en_secret_key = c.recv(1024).decode()
    c2 , c1 = format_cipher(en_secret_key)
    # print(c2)
    # print(c1)

    # print(en_secret_key)
    secret_key = decrypt(c2 , c1 , d ,prime)
    # print(secret_key)
    secret_key = ''.join(secret_key)
    secret_key = secret_key + '0011111101011001'
    print("-Decrypted Secret key:" , secret_key)
    

    ciphertext = c.recv(1024).decode()
    print("-Got Cipher Text:" , ciphertext)
    Pt = decryption(ciphertext , secret_key)

    print("-Decrypted Message:" , Pt)

    # Close the connection with the client
    c.close()

    # Breaking once connection closed
    break

