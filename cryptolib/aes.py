from Crypto.Cipher import AES
from .byte_manipulation import gen_blocks, strxor

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

def detect_aes_ecb(ct : bytes, blocksize : int = 16):
    blocks = set()
    for i in range(len(ct)//blocksize):
        block = ct[i*blocksize:(i+1)*blocksize]
        if block in blocks:
            return True
        blocks.add(block)
    return False
