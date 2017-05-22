'''
utilizzo della libreria rsa per criptare e decriptare
'''
import rsa
import os
import socket
import threading
from support import algorithm
from support import  my_rsa

IP_REC = '192.168.35.129'
PORT_REC = 12345

IP_DEST_C = '192.168.35.129'
PORT_DEST_C = 23456

FINAL_FILE = 'box.jpg'
CRYPT_FILE = 'crypted_box.jpg'

'''
prima di iniziare la generazione delle chiavi, B attende md5 e dimensione del file
da parte di A. poi genera le chiavi e manda ad A quella pubblica (n,e)
'''

'''
decifratura del file secondo le chiavi
'''

class Send_Thread(threading.Thread):
    def __init__(self, md5_orig, pub_n, pub_e, dim_file, padding, send_path):
        threading.Thread.__init__(self)
        self.md5_orig = md5_orig
        self.pub_n = pub_n
        self.pub_e = pub_e
        self.dim_file = dim_file
        self.padding = padding
        self.send_path = send_path

    def run(self):
        sock_C = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_C.connect((IP_DEST_C, PORT_DEST_C))

        sock_C.send(md5_orig.encode())
        sock_C.send(str(self.pub_n).zfill(algorithm.NUM_LONG_KEY).encode())
        sock_C.send(str(self.pub_e).zfill(algorithm.NUM_LONG_KEY).encode())

        sock_C.send(str(self.dim_file).zfill(algorithm.NUM_DIM_FILE).encode())
        sock_C.send(str(self.padding).zfill(algorithm.DIM_PADD).encode())

        ## invio del file cifrato
        algorithm.send_file(sock_C, self.send_path)

        sock_C.close()

def decypher_file(orig_file, dest_file, padding, priv_key):

    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        while read_bytes < dim_file:
            ## lettura del chunk
            chunk = file_in.read(algorithm.DIM_KEY)
            ## decifrazione del chunk ed eliminazione parte significativa
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
    print('pronto alla ricezione')
    (clientsocket, address) = sock.accept()

    ## ricezione md5 e dimensione file
    md5_orig = clientsocket.recv(algorithm.MD5_LENGTH).decode()
    print('md5 originale: ', md5_orig)

    ## generazione delle due chiavi pubblica e privata
    pub_key, priv_key = my_rsa.generate_keypair(algorithm.SMALL_P, algorithm.SMALL_Q)

    pub_e, pub_n = pub_key
    priv_d, priv_n = priv_key

    print('n ', pub_n, ' e ', pub_e)
    print('n ', priv_n,' d ', priv_d)

    ## invio della chiave pubblica n ed e
    clientsocket.send(str(pub_n).zfill(algorithm.NUM_LONG_KEY).encode())
    clientsocket.send(str(pub_e).zfill(algorithm.NUM_LONG_KEY).encode())

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
    try:
        os.remove(FINAL_FILE)
    except OSError:
        pass

    ## ricezione del file cifrato
    algorithm.recv_file(clientsocket, CRYPT_FILE, dim_file)
    print('file ricevuto: ', CRYPT_FILE)

    ## thread sottobanco che invia tutto ad C
    t_send = Send_Thread(md5_orig, pub_n, pub_e, dim_file, padding, CRYPT_FILE)
    t_send.start()

    ## decifraggio file
    decypher_file(CRYPT_FILE, FINAL_FILE, padding, (priv_d, priv_n))

    print('md5 file finale: ', algorithm.get_md5(FINAL_FILE))
    print('md5 file originale: ', md5_orig)

    clientsocket.close()
    sock.close()




