from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

aes_key = get_random_bytes(32)  # AES-256

def encrypt_file(input_path, output_path):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(iv)
        while True:
            chunk = f_in.read(1024)
            if not chunk: break
            f_out.write(cipher.encrypt(chunk))