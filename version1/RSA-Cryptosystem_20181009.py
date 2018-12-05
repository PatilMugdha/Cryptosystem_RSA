
# coding: utf-8

# In[3]:


#CS265 Crypto Project
#Fall 2018
#By Steven Yen and Mugdha Patil
#Software to implement RSA Cryptosystem

import random
from random import randrange, getrandbits

#Euclid's algorithm for determining the greatest common divisor
#Use iteration to make it faster for larger integers
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_mul_inv(x, n):
#Computes the modular multiplicative inverse of x mod n (i.e. x^-1 mod n).
#We implemented this based on the Extended Euclidean Algorithm.
    pim2=0
    pim1=1
    qim2=n//x #1
    r=n%x #11
    qim1=x//r #1
    nextdivident=r #11
    r=x%r #4
    pi = (pim2-pim1*qim2)%n

    repeat = True

    #repeatedly divide the previous divisor by the remainder until
    #the remainder becomes 0.
    while(repeat):
        pim2=pim1
        pim1=pi

        qi = nextdivident//r #11//4
        qim2=qim1
        qim1=qi

        temp = r
        r = nextdivident%r #11%4=3
        nextdivident = temp

        pi = (pim2-pim1*qim2)%n

        if (r==0):
            repeat = False

    return pi

def generate_rsa_keys(p, q):

    #compute n is product of p and q
    n = p*q

    #totient of n is product of (p-1) and (q-1)
    totient = (p-1)*(q-1)

    #choose e as a random number within range from 1 to totient
    e = random.randrange(1, totient)

    #e and totient should be coprime
    g = gcd(e, totient)
    while g != 1:
        e = random.randrange(1, totient)
        g = gcd(e, totient)

    d = mod_mul_inv(e, totient)

    #Public key:(e, n) and Private key:(d, n) 
    return ((e, n), (d, n))

def encrypt_plaintext(public_key, plain_text):
    e, n = public_key
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher_text = [pow(ord(letter),e,n) for letter in plain_text]
    #Return byte array
    return cipher_text

def decrypt_ciphertext(private_key, cipher_text):
    d, n = private_key
    #Decrypt to retrieve the plaintext with a^b mod m
    plain_text = [chr(pow(char,d,n)) for char in cipher_text]
    #Return byte array string
    return ''.join(plain_text)

def generate_random_prime(length):
    number = getrandbits(length) 
    #Check number has 1024 bits and is odd.
    number = number | (1 << length - 1) | 1
    return number

def get_prime_number(length=1024):
    prime_number = 4
    # Check if the number is prime with a primality test. 
    while not is_prime_miller_rabin_test(prime_number):
        prime_number = generate_random_prime(length)
    return prime_number 

def is_prime_miller_rabin_test(num, tests=128):
    if num == 2 or num == 3: #2 is prime. Test if num is not even.
        return True
    if num <= 1 or num % 2 == 0:
        return False
     
    #Find m and exp such that (num-1) = m*(2^exp) where r is odd according to Miller-Rabin primality test
    #anynum is in range from 1 to num-1
    exp = 0
    m = num - 1

    while m & 1 == 0: 
        exp += 1
        m //= 2
 
    #Run multiple tests 
    #Restart if the number is composite.
    for _ in range(tests):
        anynum = randrange(2, num - 1)
        x = pow(anynum, m, num)
        if x != 1 and x != num - 1:
            i = 1
            while i < exp and x != num - 1:
                x = pow(x, 2, num)
                if x == 1:
                    return False
                i += 1
            if x != num - 1:
                return False
    return True

if __name__ == '__main__':

    print ("---------------------RSA Cryptosystem-------------------------")
    p=0
    q=0
    while(p==q):
        p=get_prime_number()
        q=get_prime_number()
    
    print ("\nGenerating public/private keypairs..\n")
    public_key, private_key = generate_rsa_keys(p, q)
    print ("Public key (e, N):", public_key,"\n")
    print ("Private key (d, N):", private_key,"\n")
    message = input("Enter a message to encrypt: ")
    encrypted_msg = encrypt_plaintext(private_key, message)
    print ("\nEncrypted message: ")
    print (''.join(map(lambda x: str(x), encrypted_msg)))
    print ("\nDecrypted message: ")
    print (decrypt_ciphertext(public_key, encrypted_msg))

