from flask import Flask, render_template, send_from_directory, Response, abort
from stream_cipher import ChaoticStreamCipher
from storage import aes_key, encrypt_file
from Crypto.Cipher import AES
import os

app = Flask(__name__, template_folder='templates')

def base_path():
    return os.path.join(os.path.dirname(__file__), 'static')

def encrypted_dir():
    path = os.path.join(os.path.dirname(__file__), 'encrypted')
    os.makedirs(path, exist_ok=True)
    return path

@app.route('/')
def index():
    files = [f for f in os.listdir(base_path()) if f.lower().endswith(('.mp3', '.wav'))]
    return render_template('index.html', tracks=files)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(base_path(), filename)

@app.route('/stream/<track>/plain')
def stream_plain(track):
    path = os.path.join(base_path(), track)
    if not os.path.isfile(path): return abort(404)
    mime = 'audio/wav' if track.lower().endswith('.wav') else 'audio/mpeg'
    def generate():
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk: break
                yield chunk
    return Response(generate(), mimetype=mime)

@app.route('/stream/<track>/aes')
def stream_aes(track):
    src_path = os.path.join(base_path(), track)
    enc_path = os.path.join(encrypted_dir(), track + '.aes')
    if not os.path.isfile(src_path): return abort(404)
    if not os.path.exists(enc_path): encrypt_file(src_path, enc_path)
    return send_from_directory(encrypted_dir(), track + '.aes')

@app.route('/stream/<track>/chaotic')
def stream_chaotic(track):
    src_path = os.path.join(base_path(), track)
    enc_path = os.path.join(encrypted_dir(), track + '.aes')
    if not os.path.isfile(src_path): return abort(404)
    if not os.path.exists(enc_path): encrypt_file(src_path, enc_path)
    mime = 'audio/wav' if track.lower().endswith('.wav') else 'audio/mpeg'
    def generate():
        with open(enc_path, 'rb') as f:
            iv = f.read(16)
            aes_cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
            scc = ChaoticStreamCipher(seed=0.6)
            while True:
                chunk = f.read(1024)
                if not chunk: break
                decrypted = aes_cipher.decrypt(chunk)
                yield scc.encrypt(decrypted)
    return Response(generate(), mimetype=mime)

if __name__ == '__main__':
    app.run(port=5000, debug=True)