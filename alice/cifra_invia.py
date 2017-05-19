'''
import il pacchetto che cifra con rsa
'''
import rsa
import os
import socket
from support import algorithm

IP_DEST = '192.168.35.129'
PORT_DEST = 12345
ORIG_FILE = 'f22_raptor.jpg'
CRYPT_FILE = 'crypted_f22.bin'

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
            new_chunk = rsa.encrypt(chunk, pub_key)
            ## scrivo il file in uscita
            file_out.write(new_chunk)
            read_bytes += len(new_chunk)

            ########### stampa elaborazione avanzamento
            print('Cifraggio file con chiave A ...  ', read_bytes, ' / ', dim_file)

    print('------ Criptaggio con chiave A completo ! ------')
    print('original file dimension:  ', dim_file, 'bytes')
    print('encrypted file dimension: ', read_bytes, 'bytes')
    padding = read_bytes - dim_file
    print('necessary padding: ', padding, 'bytes')

    return padding

if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_DEST, PORT_DEST))

    ## invio md5 e dimensione del file
    md5_orig = algorithm.get_md5(ORIG_FILE)
    dim_file = os.stat(ORIG_FILE).st_size
    sock.send(md5_orig.encode())
    sock.send(str(dim_file).zfill(20).encode())
    print('md5 sent: ', md5_orig)
    print('size sent: ', dim_file)

    ## ricezione della chiave pubblica
    n = int(sock.recv(10).decode())
    e = int(sock.recv(10).decode())
    print('n ricevuto: ', n)
    print('e ricevuto ', e)

    pub_key = rsa.PublicKey(n,e)

    ## controllo se il file cifrato esiste lo elimina
    try:
        os.remove(CRYPT_FILE)
    except OSError:
        pass

    padd = cypher_file_rsa(ORIG_FILE, CRYPT_FILE, pub_key)




    '''
    implementare crittografia chunk per chunk del file e inviare il tutto
    '''


    sock.close()



