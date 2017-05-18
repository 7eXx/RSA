'''
utilizzo della libreria rsa per criptare e decriptare
'''
import rsa
import os
import socket
from support import algorithm

IP_REC = '192.168.0.197'
PORT_REC = 12345

'''
prima di iniziare la generazione delle chiavi, B attende md5 e dimensione del file
da parte di A. poi genera le chiavi e manda ad A quella pubblica (n,e)
'''

if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((IP_REC, PORT_REC))
    sock.listen(1)
    print('pronto alla ricezione')
    (clientsocket, address) = sock.accept()


    md5_orig = clientsocket.recv(algorithm.MD5_LENGTH)
    dim_file = int(clientsocket.recv(20).decode())
    print('md5 originale: ', md5_orig)
    print('dimensione originale ', dim_file)

    ## generazione delle due chiavi pubblica e privata
    (pub_key, priv_key) = rsa.newkeys(32)
    print('n ', pub_key.n, ' e ', pub_key.e)
    print('n ', priv_key.n, ' p ', priv_key.p, ' q ', priv_key.q, ' d ', priv_key.d)

    ## invio della chiave pubblica e ed n
    clientsocket.send(str(pub_key.n).zfill(10).encode())
    clientsocket.send(str(pub_key.e).zfill(10).encode())

    '''
    implementare parte ricezione del file con i metodi e decifrazione dei singoli
    chunk con la chiave privata
    '''

    clientsocket.close()
    sock.close()




