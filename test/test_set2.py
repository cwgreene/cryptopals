import cryptolib
from cryptolib import (strxor,
    aes_decrypt_ecb,
    gen_blocks,
    aes_decrypt_cbc,
    aes_encrypt_cbc,
    SwitchingEncryptionOracle,
    oracle_detect_ecb,
    SuffixECBEncryptionOracle,
    pad_pkcs7)
import base64
import os

def test_gen_blocks():
    zeros = b"\x00"*16
    ones = b"\x01"*16
    twos = b"\x02"*16
    bs = zeros + ones + twos
    blocks = list(gen_blocks(bs))
    assert blocks == [zeros,ones,twos]
        

def test_chal1():
    padded =  cryptolib.pad_pkcs7(b"YELLOW SUBMARINE", 20)
    assert len(padded) == 20
    assert padded == b"YELLOW SUBMARINE\x04\x04\x04\x04"

def test_chal2_encrypt_decrypt_cbc():
    blocks = os.urandom(8*20)
    IV = b"\x00"*16
    key = b"YELLOW SUBMARINE"
    encrypted = aes_encrypt_cbc(blocks, key, IV)
    decrypted = aes_decrypt_cbc(encrypted, key, IV)
    assert decrypted == blocks

def test_chal2_decrypt_file():
    dpath = cryptolib.datafile("10.txt")
    data = base64.b64decode(open(dpath).read())
    dpath = cryptolib.datafile("10_sol.txt")
    solution = open(dpath, "rb").read()

    IV = b"\x00"*16
    key = b"YELLOW SUBMARINE"
    plaintext = aes_decrypt_cbc(data, key, IV)

    assert solution == plaintext

def test_chal3():
    for i in range(100):
        oracle = SwitchingEncryptionOracle(os.urandom(16))
        for i in range(100):
            res = oracle_detect_ecb(oracle)
            if res:
                assert oracle.record[-1] == oracle.ecb
            else:
                assert oracle.record[-1] == oracle.cbc

def test_chal4():
    secret = base64.b64decode(open(cryptolib.datafile("12.txt")).read())
    oracle = SuffixECBEncryptionOracle(secret)
    res = oracle.encrypt(b"")

    # determine length of secret and associated
    # buffer string
    padded_length = len(res)
    buf = b""
    while padded_length == len(oracle.encrypt(buf)):
        buf += b"a"
    buf = buf[:-1]
    secret_length = padded_length - len(buf)
    known_secret = b""
    for i in range(secret_length):
        pull_buf = (len(buf) + secret_length - i)*b"a"
        test_block = (len(buf) + secret_length)//16
        for guess_char in range(256):
            first_block = "a"*((i-1) % 16)
            test = first_block + push_buf + known_secret
            result = oracle.encrypt(test)
