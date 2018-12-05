
# coding: utf-8

# In[1]:


#CS265 Crypto Project
#Fall 2018
#By Mugdha Patil and Steven Yen

#Helper methods we implemented
import math
from decimal import *
import random
from random import randrange, getrandbits

def mod_mul_inv(x, n):
    """
    Computes the modular multiplicative inverse of x mod n (i.e. x^-1 mod n).
    We implemented this based on the Extended Euclidean Algorithm.
    """
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

def kthRootOfLargeNum(numb,k):
    """
    Computes the kth root of a very large number.
    We implemented this based on suggest from stackoverflow.
    Converting the number to Decimal allows the computation to be done.
    """
    getcontext().prec = len(str(numb)) #default precision of 28 too small for the number
    numbDec = Decimal(numb) #convert int number to decimcal 
    expDec = Decimal(1)/Decimal(k) #convert exponent to decimal.
    
    kthroot = numbDec**expDec
    kthroot = int(Decimal(kthroot.quantize(Decimal('1.'), rounding=ROUND_UP))) #round to int.
     
    return kthroot


# In[2]:


def is_prime_miller_rabin_test(num):
    """
    Checks to see if the candidates generated is prime.
    It uses 150 iterations of the miller rabin test to see if the number is prime.
    we implemented this basd on the pseudocode for Miller-Rabin Primality Test (Wikipedia)
    """
    #negatives numbers and 1 are not prime.
    if num <=1:
        return False
    
    #besides from 2, all even numbers are not prime
    if (num%2)==0:
        if num==2:
            return True
        else:
            return False
        
    #rabin-miller only works for n>3, so we have to handle 3 manually
    if num==3:
        return True
        
    #find odd number m and exp such that (num-1)=m*(2**exp)
    exp=0
    m=num-1
    while(m%2==0):
        exp = exp+1
        m = m//2

    max_cycles=150
    
    while(max_cycles>0):
        #print(max_cycles)
        max_cycles-=1
        
        anynumb= randrange(2,num-1)
        rem = pow(anynumb,m,num)

        if (rem==1) or (rem==(num-1)):
            continue
        j=0
        for j in range(exp-1):
            #print(j)
            rem = pow(rem,2,num)
            if rem == (num-1):
                break
        #continue outter loop if above for-loop terminated early.        
        if(j <(exp-1-1)):
            continue
        return False
    return True


# In[3]:


def get_prime_number(digits):
    """
    This helper method generates a prime number of specified digits.
    It generates an odd number, checks if it is prime, and repeat until it is prime.
    """
    numb = getrandbits(digits)
    numb = numb | (2**(digits-1)) #ensure left-most digist is 1 so it has enough digits.
    numb = numb | 1 #ensure the right-most digit is 1, since even num cannot be prime.
    
    while(not is_prime_miller_rabin_test(numb)):
        numb = getrandbits(digits)
        numb = numb | (2**(digits-1))
        numb = numb | 1
        
    return numb


# In[4]:


def generate_p_q(digits):
    """
    Gernerate 2 different prime numbers p and q.
    """

    #First we generate 2 different prime numbers p and q 
    p = get_prime_number(digits)
    q = get_prime_number(digits)

    #if p==q then we need to regenerate until p!=q
    while(p==q):
        p = get_prime_number(digits)
        q = get_prime_number(digits)

    return (p,q)


# In[5]:


def generate_rsa_kp(digits,set_e=-1):
    """
    Generate RSA key-pairs. Public Key N, e, and private key d. It returns (N,e,d).
    if set_exp is not specified (left as -1), then we'll randomly generate one.
    if it is specified like e=3, we will try to pick p and q such that e=3.
    This is so we can pick specific exponents such as in the Alice's Birthday Party Challenge.
    Implemented based on the RSA algo described in the textbook.
    """
    
    p,q = generate_p_q(digits)
    
    #the product (p-1)*(q-1)=totient(pq).
    totient=(p-1)*(q-1)
    
    enc_exp=None
    
    #if the user picked a specific e, then we regenerate p,q until
    #it satisfieds the relationship: e is relatively prime to (p-1)(q-1)
    #else we try different e instead until it satisfies the relationship.
    if(set_e!=-1):
        enc_exp = set_e
        while(math.gcd(enc_exp,totient)!=1):
            p,q = generate_p_q(digits)
            totient=(p-1)*(q-1)
    else:
        enc_exp = random.randrange(1,totient)
        while(math.gcd(enc_exp,totient)!=1):
            enc_exp = random.randrange(1,totient)
            
    N = p*q #the encryption modulus
    
    print("\nPublic Key, (N,e):")
    print("\nEncryption Modulus: N=",N)
    print("\nEncryption Exponent: e=",enc_exp)
    
    #now we calculate the decryption exponent
    dec_exp = mod_mul_inv(enc_exp,totient)
    print("\nPrivate Key, d:")
    print("\nDecryption Exponent: d=",dec_exp)
    
    return (N, enc_exp, dec_exp)


# In[6]:


def rsa_encrypt(M,N,e):
    """
    Encrypts the message with the formula C = M^e mod N
    M = the message (or the encoding) as an integer
    e = encryption exponent
    N = encryption Modulus
    returns the ciphertext.
    """
    return pow(M,e,N)

def rsa_decrypt(C,N,d):
    """
    Descrypts the message with the formula P = C^d mod N
    M = the ciphertext
    d = descryption exponent
    N = encryption Modulus
    returns the decrypted plaintext.
    """
    return pow(C,d,N)


# In[7]:


print("\nNow we will go through an example demonstrating RSA usage.")

print("\nWe first generate the RSA key-pair.")

N,e,d = generate_rsa_kp(1024)

print("We limit M to integers because the string-to-int encoding method is not part of RSA.")
print("Users can choose different encoding schemes (encoding is not part of encryption). \n")

message = input("Please enter an integer message to encrypt: ")
message = int(message)

print("\nThe message entered is: ",message)

print("\nNow we apply the public key (N,e) to calculate ciphertext.")

C = rsa_encrypt(message,N,e) #encryption formula C = M^e mod N

print("\nThe encrypted ciphertext is: C=",C)

print("\nThe ciphertext C is what will be sent over the network from Alice to Bob.")

print("\nUpon receiving the ciphertext C, Bob will apply his private key to decrypt.")

print("\nHe simply uses the formula P = C^d mod N to decrypt.")

P = rsa_decrypt(C,N,d)

print("\nThe original message is computed as P=",P)

print("\nThis matches the original message.")

