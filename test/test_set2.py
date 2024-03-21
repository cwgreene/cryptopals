import cryptolib
from cryptolib import strxor, aes_decrypt_ecb, gen_blocks
import base64

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

def test_chal2():
    dpath = cryptolib.datafile("10.txt")
    data = base64.b64decode(open(dpath).read())
    dpath = cryptolib.datafile("10_sol.txt")
    solution = open(dpath, "rb").read()
    xor = b"\x00"*16
    plaintext = b""
    key = b"YELLOW SUBMARINE"
    for block in gen_blocks(data):
        decrypt = aes_decrypt_ecb(block, key)
        plaintext += strxor(xor, decrypt)
        xor = block
    assert solution == plaintext
