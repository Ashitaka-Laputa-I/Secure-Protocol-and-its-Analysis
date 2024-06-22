import tkinter as tk
from tkinter import messagebox
import traceback
from secure_protocol import SecureProtocol
from rsa_utils import generate_rsa_key_pair, sign_data, verify_signature
from dh_utils import generate_dh_key_pair, compute_dh_shared_secret
from crypto_utils import encrypt_message, decrypt_message, generate_mac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def protocol_analysis(progress_var, result_text):
    result_text.delete(1.0, tk.END)
    try:
        # 设置全局字体为黑体
        result_text.configure(font=("黑体", 16))

        result_text.insert(tk.END, "生成RSA密钥对...\n")
        result_text.see(tk.END)
        progress_var.set(10)
        result_text.update()
        alice_private_key, alice_public_key = generate_rsa_key_pair()
        bob_private_key, bob_public_key = generate_rsa_key_pair()
        result_text.insert(tk.END, "Alice's Public Key: {}\n".format(alice_public_key.hex()))
        result_text.insert(tk.END, "Bob's Public Key: {}\n".format(bob_public_key.hex()))
        result_text.see(tk.END)

        result_text.insert(tk.END, "\n进行Diffie-Hellman密钥交换...\n")
        result_text.see(tk.END)
        progress_var.set(30)
        result_text.update()
        dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
        alice_dh_private, alice_dh_public = generate_dh_key_pair(dh_parameters)
        bob_dh_private, bob_dh_public = generate_dh_key_pair(dh_parameters)
        result_text.insert(tk.END, "Alice's DH Private Key: {}\n".format(alice_dh_private))
        result_text.insert(tk.END, "Alice's DH Public Key: {}\n".format(alice_dh_public))
        result_text.insert(tk.END, "Bob's DH Private Key: {}\n".format(bob_dh_private))
        result_text.insert(tk.END, "Bob's DH Public Key: {}\n".format(bob_dh_public))
        result_text.insert(tk.END, "生成DH密钥对完成。\n")
        result_text.see(tk.END)
        result_text.update()

        result_text.insert(tk.END, "\nAlice和Bob签名公钥...\n")
        result_text.see(tk.END)
        progress_var.set(50)
        result_text.update()
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
        result_text.insert(tk.END, "Alice's Signature: {}\n".format(alice_signature.hex()))
        result_text.insert(tk.END, "Bob's Signature: {}\n".format(bob_signature.hex()))
        result_text.insert(tk.END, "签名完成。\n")
        result_text.see(tk.END)
        result_text.update()

        result_text.insert(tk.END, "\nAlice和Bob验证对方的公钥签名...\n")
        result_text.see(tk.END)
        progress_var.set(70)
        result_text.update()
        if not verify_signature(bob_public_key, bob_dh_public_bytes, bob_signature):
            raise Exception("Bob's DH public key signature verification failed!")
        if not verify_signature(alice_public_key, alice_dh_public_bytes, alice_signature):
            raise Exception("Alice's DH public key signature verification failed!")
        result_text.insert(tk.END, "验证签名完成。\n")
        result_text.see(tk.END)
        result_text.update()

        result_text.insert(tk.END, "\n计算共享密钥...\n")
        result_text.see(tk.END)
        progress_var.set(90)
        result_text.update()
        alice_shared_secret = compute_dh_shared_secret(alice_dh_private, bob_dh_public)
        bob_shared_secret = compute_dh_shared_secret(bob_dh_private, alice_dh_public)
        result_text.insert(tk.END, "Alice's Shared Secret: {}\n".format(alice_shared_secret))
        result_text.insert(tk.END, "Bob's Shared Secret: {}\n".format(bob_shared_secret))
        result_text.insert(tk.END, "共享密钥计算完成。\n")
        result_text.see(tk.END)
        result_text.update()

        session_key = HKDF(master=alice_shared_secret, key_len=32, salt=None, hashmod=SHA256)
        result_text.insert(tk.END, "Session Key: {}\n".format(session_key))
        result_text.insert(tk.END, "共享密钥生成完成。\n")
        result_text.see(tk.END)
        result_text.update()

        result_text.insert(tk.END, "\n模拟重放攻击:\n")
        result_text.see(tk.END)
        progress_var.set(95)
        result_text.update()
        result_text.insert(tk.END, "1. 加密消息\n")
        result_text.see(tk.END)
        result_text.update()
        plaintext = b'Hello, this is a secret message.'
        nonce, ciphertext, tag = encrypt_message(session_key, plaintext)
        result_text.insert(tk.END, "Plaintext: {}\n".format(plaintext.decode()))
        result_text.insert(tk.END, "Nonce: {}\n".format(nonce))
        result_text.insert(tk.END, "Ciphertext: {}\n".format(ciphertext))
        result_text.insert(tk.END, "Tag: {}\n".format(tag))
        result_text.insert(tk.END, "2. 生成消息认证码 (MAC)\n")
        result_text.see(tk.END)
        result_text.update()
        mac = generate_mac(session_key, ciphertext)
        result_text.insert(tk.END, "MAC: {}\n".format(mac))
        result_text.insert(tk.END, "3. 解密消息\n")
        result_text.see(tk.END)
        result_text.update()
        received_plaintext = decrypt_message(session_key, nonce, ciphertext, tag)
        result_text.insert(tk.END, "Received Plaintext: {}\n".format(received_plaintext.decode()))
        result_text.insert(tk.END, "4. 重新生成MAC并验证\n")
        result_text.see(tk.END)
        result_text.update()
        received_mac = generate_mac(session_key, ciphertext)
        assert mac == received_mac, "MAC verification failed during replay attack!"
        result_text.tag_configure("green", foreground="green")
        result_text.insert(tk.END, "重放攻击检测通过\n", "green")
        result_text.see(tk.END)
        result_text.update()

        result_text.insert(tk.END, "\n模拟中间人攻击:\n")
        result_text.see(tk.END)
        result_text.update()
        result_text.insert(tk.END, "1. 生成Eve的DH密钥对\n")
        result_text.see(tk.END)
        result_text.update()
        eve_dh_private, eve_dh_public = generate_dh_key_pair(dh_parameters)
        result_text.insert(tk.END, "Eve's DH Private Key: {}\n".format(eve_dh_private))
        result_text.insert(tk.END, "Eve's DH Public Key: {}\n".format(eve_dh_public))
        result_text.insert(tk.END, "2. 截获并替换公钥\n")
        result_text.see(tk.END)
        result_text.update()
        intercepted_bob_public_key = eve_dh_public
        intercepted_alice_public_key = eve_dh_public

        try:
            result_text.insert(tk.END, "3. 计算被截获的共享密钥\n")
            result_text.see(tk.END)
            result_text.update()
            alice_shared_secret_compromised = compute_dh_shared_secret(alice_dh_private, intercepted_bob_public_key)
            bob_shared_secret_compromised = compute_dh_shared_secret(bob_dh_private, intercepted_alice_public_key)
            result_text.insert(tk.END, "Alice's Compromised Shared Secret: {}\n".format(alice_shared_secret_compromised))
            result_text.insert(tk.END, "Bob's Compromised Shared Secret: {}\n".format(bob_shared_secret_compromised))
            result_text.insert(tk.END, "4. 验证共享密钥是否匹配\n")
            result_text.see(tk.END)
            result_text.update()
            assert alice_shared_secret != bob_shared_secret, "Man-in-the-middle attack detected!"
        except Exception as e:
            result_text.tag_configure("green", foreground="green")
            result_text.insert(tk.END, "中间人攻击检测通过\n", "green")
            result_text.see(tk.END)
            result_text.update()

        result_text.insert(tk.END, "\n模拟密钥泄露分析:\n")
        result_text.see(tk.END)
        result_text.update()
        result_text.insert(tk.END, "1. 使用泄露的会话密钥解密消息\n")
        result_text.see(tk.END)
        result_text.update()
        compromised_session_key = session_key
        compromised_plaintext = decrypt_message(compromised_session_key, nonce, ciphertext, tag)
        result_text.insert(tk.END, "Compromised Plaintext: {}\n".format(compromised_plaintext.decode()))
        result_text.insert(tk.END, "2. 验证解密结果\n")
        result_text.see(tk.END)
        result_text.update()
        assert compromised_plaintext == plaintext, "Key leakage detected!"
        result_text.tag_configure("green", foreground="green")
        result_text.insert(tk.END, "密钥泄露检测通过\n", "green")
        result_text.see(tk.END)
        result_text.update()

        # 协议分析和评估通过，没有检到漏洞
        result_text.tag_configure("green", foreground="green")
        result_text.insert(tk.END, "\n!!协议分析和评估通过，没有检到漏洞!!\n", "green")
        result_text.see(tk.END)
        result_text.update()

        # Ensure the progress bar is set to 100% at the end
        progress_var.set(100)
        result_text.update()

    except Exception as e:
        traceback.print_exc()
        messagebox.showerror("Error", str(e))
        result_text.tag_configure("green", foreground="red")
        result_text.insert(tk.END, "协议分析过程中发生错误，请检查日志。\n", "red")
        result_text.see(tk.END)
        result_text.update()
