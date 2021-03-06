import random
from support import  algorithm
import rsa


'''
Euclid's algorithm for determining the greatest common divisor
Use iteration to make it faster for larger integers
'''
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

'''
Euclid's extended algorithm for finding the multiplicative inverse of two numbers
'''
def multiplicative_inverse(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    # return a , lx, ly  # Return only positive values
    return lx

'''
Tests to see if a number is prime.
'''
def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    #n = pq
    n = p * q

    #Phi is the totient of n
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)

    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

## funzione per criptare e decriptare
## se la chiave e' compatibile con il messaggio
## la lunghezza di uscita e' coerente con l'ingresso
## la chiave di ingresso e' composta come k, n
def encrypt(pk, byte_array):
    # Unpack the key into it's components
    key, n = pk
    ## conversione bytes_array in intero
    b = int.from_bytes(byte_array, byteorder='big')
    tmp = pow(b, key, n)
    ## conversione da intero a bytes
    mess = tmp.to_bytes(algorithm.DIM_KEY, byteorder='big')
    # Return the array of bytes
    return mess

def decrypt(pk, byte_array):
    # Unpack the key into it's components
    key, n = pk
    ## conversione bytes_array in intero
    b = int.from_bytes(byte_array, byteorder='big')
    tmp = pow(b, key, n)
    ## conversione da intero a bytes
    mess = tmp.to_bytes(algorithm.DIM_CHUNK, byteorder='big')
    # Return the array of bytes
    return mess


if __name__ == '__main__':
    '''
    Detect if the script is being run directly by the user
    '''
    print( "RSA Encrypter/ Decrypter")
    print ("Generating your public/private keypairs now . . .")

    ## genera chiave a 64 bit
    ## public, private = rsa.newkeys(64)
    public, private = generate_keypair(algorithm.LONG_P_64, algorithm.LONG_Q_64)
    print ("Your public key is ", public ," and your private key is ", private)
    message = b'\xa8\x96\xd1\x1c\x85Xo\x93'

    ## encrypted_msg = encrypt((public.e, public.n), message)
    encrypted_msg = encrypt(public, message)
    print ("Your encrypted message is: ")
    print (encrypted_msg)
    print("Decrypting message with public key ", public ," . . .")
    print ("Your message is: ")
    ## print (decrypt((private.d, private.n), encrypted_msg))
    print (decrypt(private, encrypted_msg))