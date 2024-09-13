import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from eth_keys import keys
import uuid

# Fungsi untuk menghasilkan alamat dari kunci publik
def generate_address(public_key):
    public_key_bytes = keys.PublicKey(public_key).to_bytes()
    address = keys.PublicKey(public_key_bytes).to_checksum_address()
    return address

# Fungsi untuk mengenkripsi private key
def encrypt_private_key(private_key, password):
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(private_key)
    nonce = cipher.nonce
    mac = SHA256.new(ciphertext).hexdigest()
    
    # Menghasilkan kunci publik dari kunci privat
    private_key_object = keys.PrivateKey(private_key)
    public_key = private_key_object.public_key.to_bytes()
    address = generate_address(public_key)
    
    return {
        "version": 3,
        "id": str(uuid.uuid4()),
        "address": address,
        "crypto": {
            "ciphertext": ciphertext.hex(),
            "cipherparams": {
                "nonce": nonce.hex()
            },
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "salt": salt.hex(),
                "n": 2**14,  # Iterasi scrypt
                "r": 8,
                "p": 1
            },
            "mac": mac
        }
    }

# List private key dalam format hexadecimal
private_keys_hex = [
    '24090409c9325ee655e182e5ad296fde8a8abb1c6512999da7cf3af4e2eb1979',
    '24090409c9325ee655e182e5ad296fde8a8abb1c6512999da7cf3af4e2eb1974',
    # Tambahkan private key lainnya di sini jika ada
]

# Password untuk enkripsi (disarankan menggunakan kata sandi yang kuat)
password = '12345678'

# List untuk menyimpan struktur JSON dari setiap private key
wallets_list = []
for private_key_hex in private_keys_hex:
    # Konversi private key dari hexadecimal ke bytes
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Enkripsi private key
    wallet_json = encrypt_private_key(private_key_bytes, password)
    wallets_list.append(wallet_json)

# Simpan ke file JSON
with open('wallets.json', 'w') as f:
    json.dump(wallets_list, f, indent=4)

print("File JSON telah dibuat.")
