'''
utilizzo della libreria rsa per criptare e decriptare
'''
import rsa
import os
import socket
from support import algorithm

IP_REC = '192.168.0.203'
PORT_REC = 12345

FINAL_FILE = 'f22_raptor.jpg'
CRYPT_FILE = 'crypted_f22.jpg'

'''
prima di iniziare la generazione delle chiavi, B attende md5 e dimensione del file
da parte di A. poi genera le chiavi e manda ad A quella pubblica (n,e)
'''

'''
decifratura del file secondo le chiavi
'''
def decypher_file_a(orig_file, dest_file, padding, priv_key):

    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        while read_bytes < dim_file:
            ## lettura del chunk
            chunk = file_in.read(algorithm.DIM_CHUNK)
            ## decifrazione del chunk
            new_chunk = algorithm.encrypt_decrypt(priv_key, chunk)

            if read_bytes + len(chunk) == dim_file:
                new_chunk = new_chunk[:-padding]

            ## scrittura sul file di uscita e aggiornamento lettura
            file_out.write(new_chunk)
            read_bytes += len(chunk)

            ########### stampa elaborazione avanzamento
            print('Applicazione decifrazione RSA ', read_bytes, ' / ', dim_file, ' parte ', new_chunk)

    print('------ Decriptazione eseguita con RSA: ', priv_key)
    print('dimensione file iniziale: ', dim_file, 'bytes')


if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)      ## imposta riutilizzo della socket
    sock.bind((IP_REC, PORT_REC))
    sock.listen(1)
    print('pronto alla ricezione')
    (clientsocket, address) = sock.accept()

    ## ricezione md5 e dimensione file
    md5_orig = clientsocket.recv(algorithm.MD5_LENGTH).decode()
    dim_file = int(clientsocket.recv(algorithm.DIM_SIZE_FILE).decode())
    print('md5 originale: ', md5_orig)
    print('dimensione originale ', dim_file)

    ## generazione delle due chiavi pubblica e privata
    (pub_key, priv_key) = rsa.newkeys(algorithm.DIM_KEY)
    print('n ', pub_key.n, ' e ', pub_key.e)
    print('n ', priv_key.n, ' p ', priv_key.p, ' q ', priv_key.q, ' d ', priv_key.d)

    ## invio della chiave pubblica e ed n
    clientsocket.send(str(pub_key.n).zfill(algorithm.DIM_LONG_KEY).encode())
    clientsocket.send(str(pub_key.e).zfill(algorithm.DIM_LONG_KEY).encode())

    ## ricezione del padding utilizzato al cifraggio
    padding = int(clientsocket.recv(algorithm.DIM_PADD).decode())
    print('padding ricevuto: ', padding)

    ## verifica se il file esiste lo elimino
    try:
        os.remove(CRYPT_FILE)
    except OSError:
        pass
    try:
        os.remove(FINAL_FILE)
    except OSError:
        pass

    ## ricezione del file cifrato
    algorithm.recv_file(clientsocket, CRYPT_FILE, dim_file + padding)
    print('file ricevuto: ', CRYPT_FILE)

    decypher_file_a(CRYPT_FILE, FINAL_FILE, padding, (priv_key.d, priv_key.n))

    print('md5 file finale: ', algorithm.get_md5(FINAL_FILE))
    print('md5 file originale: ', md5_orig)


    '''
    implementare parte ricezione del file con i metodi e decifrazione dei singoli
    chunk con la chiave privata
    '''

    clientsocket.close()
    sock.close()




