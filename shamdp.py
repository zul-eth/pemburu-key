from Crypto.Hash import RIPEMD160,SHA256


pub_C = "0000000000000000000000000000000000000000000000000789"
hash_sha256 = SHA256.new(bytearray.fromhex(pub_C)).digest()
hash_ripemd160 = RIPEMD160.new(hash_sha256).digest()
prefix = hash_ripemd160.hex()

#print(hash_sha256.hex())
#print(hash_sha256)
#print(hash_ripemd160)
print(prefix)
print("61eb8a50c86b0584bb727dd65bed8d2400d6d5aa")