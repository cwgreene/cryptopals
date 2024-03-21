import base64
import binascii
import string
import os
import math

from Crypto.Cipher import AES

from .byte_manipulation import strxor

def decrypt_score(bs : bytes):
    printable = string.printable.encode()
    score = 0
    for b in bs:
        if b not in printable:
            score -= 255
        elif b in b"ETAOIN SHRDLUetoain shrdlu":
            score += 2
    return score

def decrypt_sb_xor(bs : bytes, s : int):
    res = []
    for b in bs:
        res.append(b^s)
    return bytes(res)

def brute_decrypt_sb_xor(bs : bytes):
    res = []
    for i in range(256):
        pt = decrypt_sb_xor(bs, i)
        res.append((decrypt_score(pt), pt, i))
    res.sort()
    return max(res), res

def brute_decrypt_rep_xor_len(bs : bytes, key_length):
    key = []
    for i in range(key_length):
        # chop
        chopped = bytes(bs[i::key_length])
        s, keyletter = brute_decrypt_sb_xor(chopped)
        key.append(keyletter[-1][2])
    return bytes(key)

def brute_decrypt_rep_xor(bs : bytes, max_len : int = 32):
    guess_len = 1
    best = (-1,b"")
    while guess_len < max_len:
        key = brute_decrypt_rep_xor_len(bs, guess_len)
        pt = decrypt_xor_repeat(bs, key)
        best = max((decrypt_score(pt), pt, key), best)
        guess_len += 1
    return best

def find_data_dir():
    import os
    curdir = os.getcwd()
    while curdir != "/": # bug if data is in root dir
        curtest = os.path.join(curdir, "data")
        if os.path.exists(curtest):
            return curtest
        curtest = os.path.realpath(os.path.join(curtest,".."))

def datafile(filename : str):
    return os.path.join(find_data_dir(), filename)

def encrypt_xor_repeat(pt, xor):
    xlen = len(xor)
    plen = len(pt)
    repcount = int(math.ceil(plen/xlen))
    return strxor(pt,xor*repcount)

def decrypt_xor_repeat(ct, xor):
    return encrypt_xor_repeat(ct, xor)

def pad_pkcs7(bs, length):
    diff = length - len(bs)
    return bs + bytes([diff])*diff

