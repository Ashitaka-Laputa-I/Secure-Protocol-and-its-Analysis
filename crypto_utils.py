import time
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

def encrypt_message(session_key, plaintext):
    time.sleep(1)
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag

def decrypt_message(session_key, nonce, ciphertext, tag):
    time.sleep(1)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def generate_mac(key, message):
    time.sleep(1)
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(message)
    return hmac.digest()

if __name__ == '__main__':
    # Testing Crypto utilities
    key = get_random_bytes(32)
    message = b'Test message for encryption and MAC'
    nonce, ciphertext, tag = encrypt_message(key, message)
    print(f"Ciphertext: {ciphertext}\nTag: {tag}")
    decrypted_message = decrypt_message(key, nonce, ciphertext, tag)
    print(f"Decrypted Message: {decrypted_message}")
    mac = generate_mac(key, ciphertext)
    print(f"MAC: {mac}")
