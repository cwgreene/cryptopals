from Crypto.Cipher import AES
import random
import os

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
    def __init__(self,
            key,
            prefix_len_range = (5,10),
            suffix_len_range = (5,10)):
        self.key = key
        self.record = []
        self.cbc = lambda data, key: aes_encrypt_cbc(data,
                        key,
                        IV=os.urandom(16))
        self.ecb = aes_encrypt_ecb
        self.prefix_len_range = prefix_len_range
        self.suffix_len_range = suffix_len_range


    def encrypt(self, data):
        prefix = os.urandom(random.randint(*self.prefix_len_range))
        suffix = os.urandom(random.randint(*self.suffix_len_range))
        data = pad(prefix + data + suffix, 16)
        which = random.choice([self.cbc, self.ecb])
        self.record.append(which)
        return which(data, self.key)

def oracle_detect_ecb(oracle : EncryptionOracle):
    result = oracle.encrypt(b"A"*32+b"A"*11)
    blocks = list(gen_blocks(result))
    if blocks[-2] == blocks[-3]:
        return True
    return False
