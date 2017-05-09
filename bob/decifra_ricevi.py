'''
utilizzo della libreria rsa per criptare e decriptare
'''
import rsa
import os
import socket
from support import algorithm

IP_REC = '192.168.0.153'
PORT_REC = 12345

if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((IP_REC, PORT_REC))
    sock.listen(1)
    print('pronto alla ricezione')
    (clientsocket, address) = sock.accept()


    md5_orig = clientsocket.recv(algorithm.MD5_LENGTH)
    print('md5 originale: ', md5_orig)

    (pub_key, priv_key) = rsa.newkeys(512)
    print(pub_key)
    print(priv_key)


