import base64
import binascii
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

s = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
b=binascii.unhexlify(s)
b2 = unhexlify(s)
print(b, b2)
assert hexlify(unhexlify(s))==s

print(base64.b64encode(b))


