from Crypto.Cipher import AES
import random

from .byte_manipulation import gen_blocks, strxor
from . import pad_pkcs7 as pad

def aes_encrypt_ecb(bs, key):
    aes = AES.new(key, mode=AES.MODE_ECB)
    return aes.encrypt(bs)

def aes_decrypt_ecb(bs, key):
    aes = AES.new(key, mode=AES.MODE_ECB)
    return aes.decrypt(bs)

def aes_decrypt_cbc(bs, key, IV):
    xor = IV
    plaintext = b""
    for block in gen_blocks(bs):
        decrypt = aes_decrypt_ecb(block, key)
        plaintext += strxor(xor, decrypt)
        xor = block
    return plaintext

def aes_encrypt_cbc(bs, key, IV):
    xor = IV
    ciphertext = b""
    assert len(IV) % 16 == 0
    for block in gen_blocks(bs):
        encrypt = aes_encrypt_ecb(strxor(block, xor), key)
        ciphertext += encrypt
        xor = encrypt
    return ciphertext


def detect_aes_ecb(ct : bytes, blocksize : int = 16):
    blocks = set()
    for i in range(len(ct)//blocksize):
        block = ct[i*blocksize:(i+1)*blocksize]
        if block in blocks:
            return True
        blocks.add(block)
    return False

class EncryptionOracle:
    def __init__(self, key):
        self.key = key
    def encrypt(self, data):
        prefix = os.urandom(random.randint(5,10))
        suffix = os.urandom(random.randint(5,10))
        cbc = lambda data, key: aes_encrypt_cbc(data, key, IV=os.urandom(16))
        data = pad(prefix + data + suffix)
        which = random.choice([aes_encrypt_ecb, cbc])
        return which(data, self.key)
