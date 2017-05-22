
import hashlib

NUM_LONG_KEY = 5       ## campo del protocollo che identifica quante cifre ha la chiave 2^DIM_KEY_BIT
NUM_DIM_FILE = 20       ## campo del protocollo che identifica quante cifre ha il file
MD5_LENGTH = 32
## NB modifica della lunghezza in bit del chunk
DIM_CHUNK_BIT = 8
DIM_PADD = 1
DIM_CHUNK = DIM_CHUNK_BIT // 8
## lunghezza della chiave
## NB la chiave deve essere maggiore del chunk
## altrimenti si che funziona il crittosistema
DIM_KEY_BIT = DIM_CHUNK_BIT*2
DIM_KEY = DIM_KEY_BIT // 8

## costanti per la generazione manuale delle chiavi
## p e q per chiave a 32 bit
LONG_P_32 = 131011
LONG_Q_32 = 25931

## p e q per chiave a 64 bit
LONG_P_64 = 16312004521
LONG_Q_64 = 718464377

## costanti piccole per bruteforce
SMALL_P = 5
SMALL_Q = 53

'''
algoritmo per calcolare l'md5
'''
def get_md5(path):
    md5 = hashlib.md5()
    with open(path,'rb') as f:
        data = f.read(1024)
        while data:
            md5.update(data)
            data = f.read(1024)

    return md5.hexdigest()


## metodo per inviare un file attraverso una socket
def send_file (sock, file_path):
    ## legge il file e lo invia un po' per volta
    with open(file_path, 'rb') as f:
        data = f.read(1024)
        while data:
            sock.send(data)
            data = f.read(1024)

## metodo per ricevere le informazioni da una socket
## e le scrive in un file
def recv_file(sock, file_path, size_tot):
    ## scrive sul file indicato
    with open(file_path, 'wb') as f:
        read_tot = 0
        while read_tot < size_tot:
            data = sock.recv(1024)
            f.write(data)
            read_tot += len(data)

## funzione per criptare e decriptare
## se la chiave e' compatibile con il messaggio
## la lunghezza di uscita e' coerente con l'ingresso
## la chiave di ingresso e' composta come k, n
def encrypt_decrypt(pk, byte_array):
    # Unpack the key into it's components
    key, n = pk
    ## conversione bytes_array in intero
    b = int.from_bytes(byte_array, byteorder='big')
    tmp = pow(b, key, n)
    ## conversione da intero a bytes
    mess = tmp.to_bytes(DIM_KEY, byteorder='big')
    # Return the array of bytes
    return mess





