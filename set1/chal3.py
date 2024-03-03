from cryptolib import unhexlify, brute_decrypt_sb_xor

print(brute_decrypt_sb_xor(unhexlify(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))[0])
