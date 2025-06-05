from flask import Flask, render_template, send_from_directory, Response, abort
from stream_cipher import ChaoticStreamCipher
from storage import aes_key, encrypt_file
from Crypto.Cipher import AES
import os

app = Flask(__name__, template_folder='templates')
# chỉ định file âm thanh 
def base_path():
    return os.path.join(os.path.dirname(__file__), 'static')
# trả về file mã hóa 
def encrypted_dir():
    path = os.path.join(os.path.dirname(__file__), 'encrypted')
    os.makedirs(path, exist_ok=True)
    return path
#Liệt kê tất cả file có đuôi .mp3 hoặc .wav trong thư mục static/.
@app.route('/')
def index():
    files = [f for f in os.listdir(base_path()) if f.lower().endswith(('.mp3', '.wav'))]
    return render_template('index.html', tracks=files)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(base_path(), filename)


#Mở file gốc (MP3/WAV) và yield từng chunk 1024 byte, streaming tới client.
#Browser (thẻ <audio>) sẽ tự động nhận chunk và buffer để phát.
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



# ... (các import và định nghĩa khác) ...

@app.route('/stream/<track>/chaotic')
def stream_chaotic(track):
    src_path = os.path.join(base_path(), track) # Đọc từ file gốc
    if not os.path.isfile(src_path): return abort(404)
    mime = 'audio/wav' if track.lower().endswith('.wav') else 'audio/mpeg'
    def generate():
        scc = ChaoticStreamCipher(seed=0.6) # Khởi tạo ChaoticStreamCipher cho mỗi request
        with open(src_path, 'rb') as f: # Mở file gốc
            while True:
                chunk = f.read(1024) # Đọc chunk từ file gốc
                if not chunk: break
                # Mã hóa chunk bằng Chaotic Stream Cipher trước khi gửi đi
                yield scc.encrypt(chunk) 
    return Response(generate(), mimetype=mime)


if __name__ == '__main__':
    app.run(port=5000, debug=True)