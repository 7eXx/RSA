'''
import il pacchetto che cifra con rsa
'''
import rsa
import os
import socket
from support import algorithm

IP_DEST = '192.168.242.130'
PORT_DEST = 12345
FILE_ORIG = 'f22_raptor.jpg'
'''
l'idea di base e' che per cominciare a dialogare, alice manda a bob
md5 del file e quindi solo dopo bob risponde con la chiave pubblica
quindi alice puo' cominciare a cifrare il file con le chiavi ricevute
'''


if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_DEST, PORT_DEST))

    md5_orig = algorithm.get_md5(FILE_ORIG)
    sock.send(md5_orig.encode())
    print('md5 sent: ', md5_orig)

    n = sock.recv(10).decode()
    e = sock.recv(10).decode()


    sock.close()



