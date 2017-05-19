'''
utilizzo della libreria rsa per criptare e decriptare
'''
import rsa
import os
import socket
from support import algorithm

IP_REC = '192.168.35.129'
PORT_REC = 12345

FINAL_FILE = 'f22_raptor.jpg'
CRYPT_FILE = 'crypted_f22.bin'

'''
prima di iniziare la generazione delle chiavi, B attende md5 e dimensione del file
da parte di A. poi genera le chiavi e manda ad A quella pubblica (n,e)
'''

'''
decifratura del file secondo le chiavi
'''
def decypher_file_a(orig_file, dest_file, padding, keys_a):

    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        for i in range(0, len(keys_a)):
            chunk = file_in.read(algorithm.DIM_CHUNK_BIT // 8)
            new_chunk = algorithm.reverse_tex_function_for_a(keys_a[i], chunk)

            file_out.write(new_chunk)
            read_bytes += len(new_chunk)

            ########### stampa elaborazione avanzamento
            print('Togliendo la chiave A ...  ', read_bytes, ' / ', os.stat(orig_file).st_size)

    print('------ Decriptazione con A ------')
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
    ## clientsocket.recv()

    '''
    implementare parte ricezione del file con i metodi e decifrazione dei singoli
    chunk con la chiave privata
    '''

    clientsocket.close()
    sock.close()




