import cryptolib
import base64

from Crypto.Cipher import AES

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
    lines = []
    with open(cryptolib.datafile("4.txt"), "rb") as afile:
        for line in afile.readlines():
            lines.append(cryptolib.unhexlify(line.strip()))
    
    pts = []
    for cipher in lines:
        (score, pt, c), _ = cryptolib.brute_decrypt_sb_xor(cipher)
        pts.append((score, pt))
    best = max(pts)[1]
    assert b"Now that the party is jumping\n" == best

def test_chal5():
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    solution = (b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
               b"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    assert cryptolib.hexlify(cryptolib.encrypt_xor_repeat(plaintext, key))==solution

def test_chal6():
    data = cryptolib.datafile("6.txt")
    data = base64.b64decode(open(data).read())
    expected = open(cryptolib.datafile("6_sol.txt"), "rb").read()
    score, solution, key = cryptolib.brute_decrypt_rep_xor(data)
    assert score > 0
    assert key == b"Terminator X: Bring the noise"
    assert solution == expected

def test_chal7():
    data = cryptolib.datafile("7.txt")
    data = base64.b64decode(open(data).read())
    expected = open(cryptolib.datafile("7_sol.txt"), "rb").read()
    aes = AES.new(key=b"YELLOW SUBMARINE", mode=AES.MODE_ECB)
    sln = aes.decrypt(data)
    assert expected == sln

def test_chal8():
    dpath = cryptolib.datafile("8.txt")
    data = open(dpath, "rb").read()
    data = [base64.b64decode(d) for d in data.split(b"\n")]
    count = 0
    for line in data:
        if cryptolib.detect_aes_ecb(line):
            count += 1
    assert count == 1
