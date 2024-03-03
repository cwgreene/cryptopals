from cryptolib import hexlify,unhexlify,strxor

assert (hexlify(
        strxor(
            unhexlify(b"1c0111001f010100061a024b53535009181c"),
            unhexlify(b"686974207468652062756c6c277320657965")))
    ==b"746865206b696420646f6e277420706c6179")
print("Success")
