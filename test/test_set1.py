import cryptolib
import base64

def test_chal1():
    assert (base64.b64encode(
        cryptolib.unhexlify(b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
        == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
def test_chal2():
    s1 = cryptolib.unhexlify(b"1c0111001f010100061a024b53535009181c")
    s2 = cryptolib.unhexlify(b"686974207468652062756c6c277320657965")
    s3 = cryptolib.strxor(s1,s2)
    s4 = cryptolib.hexlify(s3)
    assert s4==b"746865206b696420646f6e277420706c6179"

def test_chal3():
    bs = cryptolib.unhexlify(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    (score, best, c), _ = cryptolib.brute_decrypt_sb_xor(bs)
    assert best==b"Cooking MC's like a pound of bacon"

def test_chal4():
    with open(cryptolib.datafile("4.txt"), "rb") as afile:
        for line in afile.readlines():
            line = line.strip()
    assert False
