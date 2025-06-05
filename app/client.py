import requests
from stream_cipher import ChaoticStreamCipher

URL = 'http://localhost:5000/track'

def download_and_decrypt(output_path):
    scc = ChaoticStreamCipher(seed=0.6)
    with requests.get(URL, stream=True) as r, open(output_path, 'wb') as f_out:
        for chunk in r.iter_content(chunk_size=1024):
            if not chunk:
                break
            dec = scc.decrypt(chunk)
            f_out.write(dec)
    print(f"Decrypted track saved to {output_path}")

if __name__ == '__main__':
    download_and_decrypt('decrypted_stream.mp3')
