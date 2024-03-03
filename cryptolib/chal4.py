import binascii
import string

with open("./4.txt", "rb") as f:
    bs = f.read()

def check_xor(bs):
    for c in range(256):
        r = []
        for b in bs:
            if (b^c) in string.printable.encode():
                r.append(b^c)
            else:
                break
        if len(r) == len(bs):
            yield bytes(r)

for line in bs.split(b"\n"):
    for res in check_xor(binascii.unhexlify(line)):
        print(res)
