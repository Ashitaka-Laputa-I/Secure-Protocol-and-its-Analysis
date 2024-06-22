from rsa_utils import generate_rsa_key_pair, sign_data, verify_signature
from dh_utils import generate_dh_key_pair, compute_dh_shared_secret
from crypto_utils import encrypt_message, decrypt_message, generate_mac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

class SecureProtocol:
    def __init__(self):
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

    def authenticate_and_establish_key(self):
        # 1. Generate RSA key pairs for Alice and Bob
        alice_private_key, alice_public_key = generate_rsa_key_pair()
        bob_private_key, bob_public_key = generate_rsa_key_pair()

        # 2. Generate DH key pairs for Alice and Bob
        alice_dh_private, alice_dh_public = generate_dh_key_pair(self.dh_parameters)
        bob_dh_private, bob_dh_public = generate_dh_key_pair(self.dh_parameters)

        # 3. Sign DH public keys
        alice_dh_public_bytes = alice_dh_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        bob_dh_public_bytes = bob_dh_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        alice_signature = sign_data(alice_private_key, alice_dh_public_bytes)
        bob_signature = sign_data(bob_private_key, bob_dh_public_bytes)

        # 4. Verify DH public keys
        if not verify_signature(bob_public_key, bob_dh_public_bytes, bob_signature):
            raise Exception("Bob's DH public key signature verification failed!")
        if not verify_signature(alice_public_key, alice_dh_public_bytes, alice_signature):
            raise Exception("Alice's DH public key signature verification failed!")

        # 5. Compute shared secrets
        alice_shared_secret = compute_dh_shared_secret(alice_dh_private, bob_dh_public)
        bob_shared_secret = compute_dh_shared_secret(bob_dh_private, alice_dh_public)

        # 6. Derive session key
        session_key = HKDF(master=alice_shared_secret, key_len=32, salt=None, hashmod=SHA256)

        return alice_private_key, alice_public_key, bob_private_key, bob_public_key, session_key

    def secure_message_exchange(self, session_key):
        # Encrypt message
        plaintext = b'Hello, this is a secret message.'
        nonce, ciphertext, tag = encrypt_message(session_key, plaintext)

        # Generate MAC
        mac = generate_mac(session_key, ciphertext)

        # Decrypt message
        received_plaintext = decrypt_message(session_key, nonce, ciphertext, tag)

        # Verify MAC
        received_mac = generate_mac(session_key, ciphertext)
        assert mac == received_mac, "MAC verification failed!"

        return plaintext, received_plaintext, mac, received_mac
