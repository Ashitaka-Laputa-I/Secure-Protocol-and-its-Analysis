import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def generate_dh_key_pair(parameters):
    time.sleep(1)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_dh_shared_secret(private_key, public_key):
    time.sleep(1)
    shared_key = private_key.exchange(public_key)
    return shared_key

if __name__ == '__main__':
    # Testing DH utilities
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    priv_key, pub_key = generate_dh_key_pair(parameters)
    print(f"Private Key: {priv_key}\nPublic Key: {pub_key}")
    shared_secret = compute_dh_shared_secret(priv_key, pub_key)
    print(f"Shared Secret: {shared_secret}")
