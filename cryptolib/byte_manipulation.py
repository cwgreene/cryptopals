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

def gen_blocks(bs, blocklength : int = 16):
    for i in range(len(bs)//blocklength):
        yield bs[i*blocklength:(i+1)*blocklength]
