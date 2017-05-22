'''
import il pacchetto che cifra con rsa
'''
import rsa
import os
import socket
from support import algorithm
from support import my_rsa

IP_DEST_B = '192.168.35.129'
IP_DEST_C = '192.168.35.129'

PORT_DEST_B = 12345
PORT_DEST_C = 23456

ORIG_FILE = 'box.jpg'
CRYPT_FILE = 'crypted_box.jpg'

'''
l'idea di base e' che per cominciare a dialogare, alice manda a bob
md5 del file e quindi solo dopo bob risponde con la chiave pubblica
quindi alice puo' cominciare a cifrare il file con le chiavi ricevute
'''

def cypher_file_rsa(orig_file, dest_file, pub_key):
    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        while read_bytes < dim_file:
            chunk = file_in.read(algorithm.DIM_CHUNK)

            ## verifica vengono letti meno di 8 byte aggiunge il pagging
            if len(chunk) < algorithm.DIM_CHUNK:
                padding = algorithm.DIM_CHUNK - len(chunk)
                chunk += bytes(padding)

            ## cifro il chunk
            new_chunk = algorithm.encrypt_decrypt(pub_key, chunk)
            ## scrivo il file in uscita
            file_out.write(new_chunk)
            read_bytes += len(chunk)

            ########### stampa elaborazione avanzamento
            print('Cifraggio file con RSA ...  ', read_bytes, ' / ', dim_file, ' parte ', chunk)

    print('------ Criptaggio con chiave RSA  ------')
    print('chiavi: ', pub_key)
    print('original file dimension:  ', dim_file, 'bytes')
    print('encrypted file dimension: ', read_bytes, 'bytes')
    padding = read_bytes - dim_file

    return padding

if __name__ == '__main__':

    sock_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_B.connect((IP_DEST_B, PORT_DEST_B))

    ## invio md5
    md5_orig = algorithm.get_md5(ORIG_FILE)
    print('md5 sent: ', md5_orig)
    sock_B.send(md5_orig.encode())


    ## ricezione della chiave pubblica
    n = int(sock_B.recv(algorithm.NUM_LONG_KEY).decode())
    e = int(sock_B.recv(algorithm.NUM_LONG_KEY).decode())
    print('n ricevuto: ', n)
    print('e ricevuto ', e)

    ## controllo se il file cifrato esiste lo elimina
    try:
        os.remove(CRYPT_FILE)
    except OSError:
        pass

    ## cifratura, recupero del padd necessario e della dimensione del cifrato
    padd = cypher_file_rsa(ORIG_FILE, CRYPT_FILE, (e, n))
    dim_file = os.stat(CRYPT_FILE).st_size
    print('size sent: ', dim_file)
    print('padding necessario: ', padd, 'bytes')

    sock_B.send(str(dim_file).zfill(algorithm.NUM_DIM_FILE).encode())
    sock_B.send(str(padd).zfill(algorithm.DIM_PADD).encode())

     ## invio del file cifrato
    algorithm.send_file(sock_B, CRYPT_FILE)

    sock_B.close()


