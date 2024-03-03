import base64
import binascii
import string

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
def strxor(bs1, bs2):
    res = []
    for (a,b) in zip(bs1,bs2):
        res.append(a^b)
    return bytes(res)

def decrypt_score(bs):
    printable = string.printable.encode()
    score = 0
    for b in bs:
        if b not in printable:
            score -= 255
        elif b in b"ETAOIN SHRDLUetoain shrdlu":
            score += 2
    return score

def decrypt_sb_xor(bs, s):
    res = []
    for b in bs:
        res.append(b^s)
    return bytes(res)

def brute_decrypt_sb_xor(bs):
    res = []
    for i in range(256):
        pt = decrypt_sb_xor(bs, i)
        res.append((decrypt_score(pt), pt))
    return max(res), res
