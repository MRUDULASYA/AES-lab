from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16  # AES block size

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def derive_key(password: str, salt: bytes, key_len: int = 32) -> bytes:
    return PBKDF2(password, salt, dkLen=key_len, count=100_000)

def encrypt(plaintext: str, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pkcs7_pad(plaintext.encode()))
    return salt + iv + ciphertext

def decrypt(ciphertext: bytes, password: str) -> str:
    salt = ciphertext[:16]
    iv = ciphertext[16:32]
    ct = ciphertext[32:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    return pkcs7_unpad(padded).decode()

if __name__ == "__main__":
    message = "Hello, this is AES encryption demo!"
    password = "StrongPassword123"

    print("Plaintext:", message)

    encrypted = encrypt(message, password)
    print("Ciphertext (hex):", encrypted.hex())

    decrypted = decrypt(encrypted, password)
    print("Decrypted:", decrypted)
