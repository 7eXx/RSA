
import hashlib

MD5_LENGTH = 32

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