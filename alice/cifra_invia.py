'''
import il pacchetto che cifra con rsa
'''
import rsa
import os
import socket
from support import algorithm
from support import my_rsa

IP_DEST = '192.168.0.203'
PORT_DEST = 12345
ORIG_FILE = 'f22_raptor.jpg'
CRYPT_FILE = 'crypted_f22.jpg'

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
            read_bytes += len(new_chunk)

            ########### stampa elaborazione avanzamento
            print('Cifraggio file con RSA ...  ', read_bytes, ' / ', dim_file, ' parte ', chunk)

    print('------ Criptaggio con chiave RSA  ------')
    print('chiavi: ', pub_key)
    print('original file dimension:  ', dim_file, 'bytes')
    print('encrypted file dimension: ', read_bytes, 'bytes')
    padding = read_bytes - dim_file

    return padding

if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_DEST, PORT_DEST))

    ## invio md5 e dimensione del file originale
    md5_orig = algorithm.get_md5(ORIG_FILE)
    dim_file = os.stat(ORIG_FILE).st_size
    sock.send(md5_orig.encode())
    sock.send(str(dim_file).zfill(algorithm.DIM_SIZE_FILE).encode())
    print('md5 sent: ', md5_orig)
    print('size sent: ', dim_file)

    ## ricezione della chiave pubblica
    n = int(sock.recv(algorithm.DIM_LONG_KEY).decode())
    e = int(sock.recv(algorithm.DIM_LONG_KEY).decode())
    print('n ricevuto: ', n)
    print('e ricevuto ', e)

    ## controllo se il file cifrato esiste lo elimina
    try:
        os.remove(CRYPT_FILE)
    except OSError:
        pass

    ## cifratura, recupero del padd necessario e invio di tale
    padd = cypher_file_rsa(ORIG_FILE, CRYPT_FILE, (e, n))
    print('padding necessario: ', padd, 'bytes')
    sock.send(str(padd).zfill(algorithm.DIM_PADD).encode())


    algorithm.send_file(sock, CRYPT_FILE)


    '''
    implementare crittografia chunk per chunk del file e inviare il tutto
    '''


    sock.close()



