import struct
import requests
from stream_cipher import ChaoticStreamCipher

URL = 'http://localhost:5000/stream/myfile.mp3/chaotic'  # sửa cho đúng endpoint

def read_exact(stream, size):
    buf = b''
    while len(buf) < size:
        chunk = stream.read(size - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

def download_and_decrypt(output_path):
    with requests.get(URL, stream=True) as r, open(output_path, 'wb') as f_out:
        r.raw.decode_content = False

        while True:
            # 1) Đọc 8 byte header chứa seed
            header = read_exact(r.raw, 8)
            if len(header) < 8:
                break
            seed = struct.unpack('!d', header)[0]

            # 2) Tạo cipher với seed
            cipher = ChaoticStreamCipher(seed=seed, mu=3.99)

            # 3) Đọc chunk mã hoá (có thể <1024 tại cuối file)
            encrypted_chunk = read_exact(r.raw, 1024)
            if not encrypted_chunk:
                break

            # 4) Giải mã và ghi ra file
            decrypted = cipher.decrypt(encrypted_chunk)
            f_out.write(decrypted)

    print(f"Decrypted track saved to {output_path}")

if __name__ == '__main__':
    download_and_decrypt('decrypted_stream.mp3')
