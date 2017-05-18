'''
import il pacchetto che cifra con rsa
'''
import rsa
import os
import socket
from support import algorithm

IP_DEST = '192.168.0.197'
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
    dim_file = os.stat(FILE_ORIG).st_size
    sock.send(md5_orig.encode())
    sock.send(str(dim_file).zfill(20).encode())
    print('md5 sent: ', md5_orig)
    print('size sent: ', dim_file)

    n = int(sock.recv(10).decode())
    e = int(sock.recv(10).decode())

    print('n ricevuto: ', n)
    print('e ricevuto ', e)

    '''
    implementare crittografia chunk per chunk del file e inviare il tutto
    '''


    sock.close()



