from Crypto.Hash import RIPEMD160,SHA256


with open("pub.txt","r") as m:
    add = m.read().split()
pub = set(add)

for i in pub:
  x = "".join(i)
  hash_sha256 = SHA256.new(bytearray.fromhex(x)).digest()
  hash_ripemd160 = RIPEMD160.new(hash_sha256).digest()
  prefix = hash_ripemd160.hex()
  print(prefix)
  f=open(u"130.txt","a") 
  f.write(str(prefix) + '\n')
  f.close()
  
