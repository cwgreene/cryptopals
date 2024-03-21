import base64
import binascii
import string
import os
import math

# chal 1
def unhexlify(bs):
    index = b"0123456789abcdef"
    res = []
    if len(bs) % 2 != 0:
        raise Exception("Odd number of input bytes to unhexlify")
    for i in range(len(bs)//2):
        c1 = bs[2*i]  
        c2 = bs[2*i+1]
        if c1 not in index or c2 not in index:
            raise Exception(f"Cannot decode '{chr(c)}'")
        res.append(16*index.index(c1) + index.index(c2))
    return bytes(res)

def hexlify(bs):
    index = b"0123456789abcdef"
    res = []
    for b in bs:
        res.append(index[b>>4])
        res.append(index[b%16])
    return bytes(res)

#chal 2
def strxor(bs1 : bytes, bs2 : bytes):
    res = []
    for (a,b) in zip(bs1,bs2):
        res.append(a^b)
    return bytes(res)

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
