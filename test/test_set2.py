import cryptolib
from cryptolib import (strxor,
    aes_decrypt_ecb,
    gen_blocks,
    aes_decrypt_cbc,
    aes_encrypt_cbc,
    SwitchingEncryptionOracle,
    oracle_detect_ecb,
    SuffixECBEncryptionOracle,
    SuffixECBEncryptionOracleWithRandomPrefix,
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
        

def test_chal9():
    padded =  cryptolib.pad_pkcs7(b"YELLOW SUBMARINE", 20)
    assert len(padded) == 20
    assert padded == b"YELLOW SUBMARINE\x04\x04\x04\x04"

def test_chal10_encrypt_decrypt_cbc():
    blocks = os.urandom(8*20)
    IV = b"\x00"*16
    key = b"YELLOW SUBMARINE"
    encrypted = aes_encrypt_cbc(blocks, key, IV)
    decrypted = aes_decrypt_cbc(encrypted, key, IV)
    assert decrypted == blocks

def test_chal10_decrypt_file():
    dpath = cryptolib.datafile("10.txt")
    data = base64.b64decode(open(dpath).read())
    dpath = cryptolib.datafile("10_sol.txt")
    solution = open(dpath, "rb").read()

    IV = b"\x00"*16
    key = b"YELLOW SUBMARINE"
    plaintext = aes_decrypt_cbc(data, key, IV)

    assert solution == plaintext

def test_chal11():
    for i in range(100):
        oracle = SwitchingEncryptionOracle(os.urandom(16))
        for i in range(100):
            res = oracle_detect_ecb(oracle)
            if res:
                assert oracle.record[-1] == oracle.ecb
            else:
                assert oracle.record[-1] == oracle.cbc

def test_chal12():
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
        pull_buf = (len(buf) + secret_length - (i+1))*b"a"
        # Layout is
        # - Bunch of A's with guess
        # - Bunch of A's with pulled value
        # - Suffix
        # Always compare the last block of the first bunch of a's
        # with the last block of the second bunch of as
        for guess_char in range(256):
            guess_char = bytes([guess_char])
            first_blocks = pull_buf + known_secret + guess_char
            index = len(first_blocks)//16 - 1
            index2 = 2*len(first_blocks)//16 - 1
            test = first_blocks + pull_buf
            result = oracle.encrypt(test)
            result_blocks = list(gen_blocks(result))
            if result_blocks[index] == result_blocks[index2]:
                known_secret += guess_char
                break
    assert known_secret == secret#

def test_chal14():
    secret = base64.b64decode(open(cryptolib.datafile("12.txt")).read())
    oracle = SuffixECBEncryptionOracleWithRandomPrefix(secret)

    # The following signature will be two repeated blocks
    # followed by another two *different* ones.
    # Actually, we can probably just grab all the AAABBB
    # combos and look for those.
    signature = b"A"*32+b"B"*32
    def find_signature(blocks):
        i = 0
        while blocks[i] != blocks[i+1]:
            i += 1
            if i + 3 >= len(blocks):
                return None
        # The A block should be different than the B block.
        if blocks[i+2] == blocks[i+3] and blocks[i]!=blocks[i+2]:
            return i
        return None

    # determine length of secret and associated
    # buffer string
    buf = signature
    # need to do signature detection here as well
    # so that we can accurately detect the message length.
    padded_length = None
    while True:
        res = oracle.encrypt(buf)
        blocks = list(gen_blocks(res))
        if (i:=find_signature(blocks)):
            if padded_length == None:
                padded_length = len(res[i*16:])
            elif padded_length == len(res[i*16:]):
                buf += b"a"
            else:
                break
    buf = buf[:-1]
    secret_length = padded_length - len(buf)
    known_secret = b""
    assert secret_length == len(secret)
    for i in range(secret_length):
        pull_buf = (len(buf) + secret_length - (i+1))*b"a"
        # Layout is
        # - Prefix, which we assume is 16 byte aligned. It will
        #   be 1/16th of the time
        # - Bunch of A's with guess
        # - Bunch of A's with pulled value
        # - Suffix
        # Always compare the last block of the first bunch of a's
        # with the last block of the second bunch of as


        # So we optimistically guess that we're aligned.
        # and we just need to find the start of the ECB.
        for guess_char in range(256):
            guess_char = bytes([guess_char])
            first_blocks = pull_buf + known_secret + guess_char
            # layout
            index = len(first_blocks)//16 - 1
            index2 = 2*len(first_blocks)//16 - 1
            test = signature + first_blocks + pull_buf
            start_index = None
            # Keep trying unitl we get a result with
            # aligned random bytes
            while start_index == None:
                result = oracle.encrypt(test)
                result_blocks = list(gen_blocks(result))
                start_index = find_signature(result_blocks)
            index += start_index + 4 # remember to add back in the signature offset
            index2 += start_index + 4
            if result_blocks[index] == result_blocks[index2]:
                known_secret += guess_char
                break

    assert known_secret == secret
