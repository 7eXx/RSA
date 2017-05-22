
import rsa
import os
import socket
from support import algorithm
from support import  my_rsa

IP_REC = '192.168.35.129'
PORT_REC = 23456

FINAL_FILE = 'box.jpg'
CRYPT_FILE = 'crypted_box.jpg'

def decypher_file(orig_file, dest_file, padding, priv_key):

    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        while read_bytes < dim_file:
            ## lettura del chunk
            chunk = file_in.read(algorithm.DIM_KEY)
            ## NB decifrazione del chunk ed
            ## eliminazione della parte significativa
            new_chunk = algorithm.encrypt_decrypt(priv_key, chunk)
            new_chunk = new_chunk[algorithm.DIM_CHUNK:]

            if read_bytes + len(chunk) == dim_file:
                new_chunk = new_chunk[:algorithm.DIM_CHUNK-padding]

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
    print('ricezione cracker')
    (clientsocket, address) = sock.accept()

    ## ricezione md5 e dimensione file
    md5_orig = clientsocket.recv(algorithm.MD5_LENGTH).decode()
    print('md5 originale: ', md5_orig)

    ## ricezione chiave pubblica
    pub_n = int(clientsocket.recv(algorithm.NUM_LONG_KEY).decode())
    pub_e = int(clientsocket.recv(algorithm.NUM_LONG_KEY).decode())


    ## ricezione del padding utilizzato al cifraggio e della dimensione del file cifrato
    dim_file = int(clientsocket.recv(algorithm.NUM_DIM_FILE).decode())
    print('dimensione originale ', dim_file)
    padding = int(clientsocket.recv(algorithm.DIM_PADD).decode())
    print('padding ricevuto: ', padding)

    ## verifica se il file esiste lo elimino
    try:
        os.remove(CRYPT_FILE)
    except OSError:
        pass


    ## ricezione del file cifrato
    algorithm.recv_file(clientsocket, CRYPT_FILE, dim_file)
    print('file ricevuto: ', CRYPT_FILE)

    '''
    implemnetazione algoritmo bruteforce
    '''

    i = 0
    trovato = False

    while i < pub_n and not(trovato):

        try:
            os.remove(FINAL_FILE)
        except OSError:
            pass

        print("Provo con la chiave ", i, "...")
        decypher_file(CRYPT_FILE, FINAL_FILE, padding, (i, pub_n))

        if algorithm.get_md5(FINAL_FILE) == md5_orig:
            print("Bruteforce riuscito")
            trovato = True
        else:
            print("Bruteforce non riuscito")

        i += 1

    print('md5 file finale: ', algorithm.get_md5(FINAL_FILE))
    print('md5 file originale: ', md5_orig)

    clientsocket.close()
    sock.close()
