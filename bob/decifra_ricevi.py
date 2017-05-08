'''
utilizzo della libreria rsa per criptare e decriptare
'''
import rsa
import os
import socket

IP_REC = '192.168.0.125'
PORT_REC = 12345

if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind()
    sock.listen(1)

    (clientsocket, address) = socket.accept()

    (pub_key, priv_key) = rsa.newkeys(512)
    print(pub_key)
    print(priv_key)


