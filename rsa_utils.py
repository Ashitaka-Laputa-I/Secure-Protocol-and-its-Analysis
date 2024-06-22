import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def generate_rsa_key_pair():
    time.sleep(1)
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_data(private_key, data):
    time.sleep(1)
    private_key = RSA.import_key(private_key)
    hash_value = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hash_value)
    return signature

def verify_signature(public_key, data, signature):
    time.sleep(1)
    public_key = RSA.import_key(public_key)
    hash_value = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(hash_value, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == '__main__':
    # Testing RSA utilities
    priv_key, pub_key = generate_rsa_key_pair()
    print(f"Private Key: {priv_key}\nPublic Key: {pub_key}")
    message = b"Test message"
    signature = sign_data(priv_key, message)
    is_verified = verify_signature(pub_key, message, signature)
    print(f"Signature: {signature}\nVerified: {is_verified}")
