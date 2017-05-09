'''
import il pacchetto che cifra con rsa
'''
import rsa
import os
import socket
from support import algorithm

IP_DEST = '192.168.0.153'
PORT_DEST = 12345
FILE_ORIG = 'f22_raptor.jpg'

if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_DEST, PORT_DEST))

    md5_orig = algorithm.get_md5(FILE_ORIG)
    sock.send(md5_orig.encode())
    print('md5 orig: ', md5_orig)

