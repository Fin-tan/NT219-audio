import os
import secrets # Để tạo khóa/seed ngẫu nhiên an toàn
from flask import Flask, render_template, request, session, redirect, url_for, Response, abort, send_from_directory
from flask_session import Session # Để quản lý session
from storage_gcm_db import get_encrypted_blob, kms_client as kms
import sqlite3

# Giả định ChaoticStreamCipher và aes_key đã được định nghĩa
from stream_cipher import ChaoticStreamCipher
# from storage import aes_key # Nếu bạn muốn dùng aes_key từ file khác
from storage_gcm_db import init_db, encrypt_and_save_to_db, get_encrypted_blob
from Crypto.Cipher import AES as PyAES  # Dùng để giải mã AES-CFB nếu cần
# >>> ECC START: import thêm cho ECDH + AESGCM
import os, base64, secrets
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# <<< ECC END
app = Flask(__name__, template_folder='templates')

# --- Cấu hình Session ---
app.config['SECRET_KEY'] = secrets.token_hex(16) # Rất quan trọng! Thay đổi trong sản phẩm!
app.config['SESSION_TYPE'] = 'filesystem'  # Lưu session trên filesystem (đơn giản cho demo)
app.config['SESSION_COOKIE_SECURE'] = True # Chỉ gửi cookie qua HTTPS (nên dùng trong sản phẩm)
app.config['SESSION_COOKIE_HTTPONLY'] = True # Ngăn JS truy cập cookie (nên dùng)
Session(app)
# ------------------------
# >>> ECC START: khởi tạo ECC key pair server
server_priv_key = ec.generate_private_key(ec.SECP256R1())
server_pub_key = server_priv_key.public_key()
server_pub_pem = server_pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
# <<< ECC END
# --- Cấu hình đường dẫn file ---
BASE_PATH = os.path.join(os.path.dirname(__file__), 'static')
ENCRYPTED_DIR = os.path.join(os.path.dirname(__file__), 'encrypted')
DB_PATH = os.path.join(os.path.dirname(__file__), 'tracks.db')

if not os.path.exists(ENCRYPTED_DIR):
    os.makedirs(ENCRYPTED_DIR)

# --- Helper function để lấy danh sách tracks ---
def get_tracks():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM tracks_gcm;")
    tracks = [row[0] for row in cursor.fetchall()]
    conn.close()
    return tracks


# --- USER MOCK (Thay thế bằng database trong thực tế) ---
USERS = {'user': 'password123'} # Tài khoản demo
# ----------------------------------------------------

# --- Route Trang chủ ---
@app.route('/')
def index():
    # Kiểm tra xem người dùng đã đăng nhập chưa
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login')) # Chuyển hướng đến trang đăng nhập
    
    tracks = get_tracks()
    return render_template('index.html', tracks=tracks, username=session.get('username', 'Guest'))

# --- Route Đăng nhập ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in USERS and USERS[username] == password:
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True # Session kéo dài (cấu hình trong app.config)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Tên đăng nhập hoặc mật khẩu không đúng!')
    return render_template('login.html')

# --- Route Đăng xuất ---
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    # Xóa bất kỳ khóa session nào đã tạo
    session.pop('chaotic_seed', None) 
    return redirect(url_for('login'))
#-- router cung cấp key pem
@app.route('/ecdh/server_pub_key')
def get_server_pub_key():
    return Response(server_pub_pem, mimetype='application/octet-stream')

# --- Route mới để CẤP KHÓA THEO SESSION ---
@app.route('/ecdh/request_seed', methods=['POST'])
def ecdh_request_seed():
    data = request.get_json()
    client_pub_b64 = data.get('client_pub')
    if not client_pub_b64:
        abort(400, "Missing client public key")

    # >>> CHỖ SỬA: decode base64 DER và load bằng load_der_public_key
    raw = base64.b64decode(client_pub_b64)
    try:
        client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as e:
        app.logger.error(f"Invalid raw public key: {e}")
        abort(400, "Invalid client public key format")

    # Derive shared secret
    shared = server_priv_key.exchange(ec.ECDH(), client_pub)

    # HKDF → 32 bytes key
    aes_key_derived = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b'chaotic-seed'
    ).derive(shared)

    # Tạo và lưu seed Chaotic
    random_seed = secrets.randbelow(1_000_000_000) / 1_000_000_000.0
    session['chaotic_seed'] = random_seed

    # AES-GCM encrypt seed
    aesgcm = AESGCM(aes_key_derived)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, str(random_seed).encode(), None)

    return {
        'iv': base64.b64encode(iv).decode(),
        'encrypted_seed': base64.b64encode(ciphertext).decode()
    }
# --- Route Streaming Chaotic (đã chỉnh sửa để dùng khóa từ session) ---
@app.route('/stream/<track>/chaotic')
def stream_chaotic(track):
    if 'logged_in' not in session or not session['logged_in']:
        return abort(401) # Unauthorized
    
    # Lấy seed từ session. Nếu không có, có thể do chưa gọi get_chaotic_session_key
    chaotic_seed = session.get('chaotic_seed')
    if chaotic_seed is None:
        return abort(400, "Chaotic session key not established. Please request key first.")

    # Bước 2: Lấy blob AES-GCM từ DB
    record = get_encrypted_blob(track)
    if record is None:
        return abort(404, f"Track '{track}' chưa được mã hoá trong database.")
    encrypted_key_blob, data_blob = record

    # Bước 3: Dùng KMS giải mã data-key
    try:
        kms_resp = kms.decrypt(CiphertextBlob=encrypted_key_blob)
        data_key_plain = kms_resp['Plaintext']
    except Exception as e:
        app.logger.error(f"KMS decrypt data key failed: {e}")
        return abort(500, "Internal decryption error.")

    # Bước 4: Tách nonce, tag, ciphertext
    nonce, tag, ciphertext = data_blob[:12], data_blob[12:28], data_blob[28:]

    # Bước 5: Giải mã AES-GCM để lấy plaintext toàn bộ file
    try:
        aes_cipher = PyAES.new(data_key_plain, PyAES.MODE_GCM, nonce=nonce)
        plaintext_all = aes_cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        app.logger.error(f"AES-GCM decrypt failed for {track}: {e}")
        return abort(500, "AES-GCM decrypt failed.")

    def generate():
        scc = ChaoticStreamCipher(seed=chaotic_seed, mu=3.99)
        chunk_size = 1024
        for i in range(0, len(plaintext_all), chunk_size):
            plain_chunk = plaintext_all[i:i+chunk_size]
            yield scc.encrypt(plain_chunk)

    mime = 'audio/wav' if track.lower().endswith('.wav') else 'audio/mpeg'
    return Response(generate(), mimetype=mime)
# --- Các route khác (plain, aes) có thể giữ nguyên hoặc chỉnh sửa tương tự ---
@app.route('/static/<path:filename>')
def serve_static(filename):
    if 'logged_in' not in session or not session['logged_in']:
        return abort(401) # Unauthorized
    return send_from_directory(BASE_PATH, filename)

# Route stream AES (ví dụ, cần chỉnh sửa để dùng key từ session hoặc quản lý key an toàn hơn)
@app.route('/stream/<track>/aes_encrypted')
def stream_aes_encrypted(track):
    if 'logged_in' not in session or not session['logged_in']:
        return abort(401) # Unauthorized
    # ... logic mã hóa AES và gửi file (cần quản lý key AES an toàn hơn)
    # Tạm thời trả về file đã mã hóa nếu có
    enc_path = os.path.join(ENCRYPTED_DIR, track + '.aes')
    if not os.path.isfile(enc_path):
        # Đây chỉ là ví dụ, trong thực tế bạn không nên mã hóa lại mỗi lần
        # Bạn sẽ cần logic để mã hóa 1 lần khi upload hoặc dùng MediaBox/ffmpeg
        # Để đơn giản, giả định file đã tồn tại cho demo
        return abort(404, "Encrypted AES file not found.")
    return send_from_directory(ENCRYPTED_DIR, track + '.aes')
@app.route('/stream/<track>/aesgcm')
def stream_aesgcm(track):
    # Trả về nguyên blob (nonce‖tag‖ciphertext) để JS client giải mã AES-GCM
    blob = get_encrypted_blob(track)
    if blob is None:
        return abort(404, f"Track '{track}' chưa được mã hoá trong database.")
    return Response(blob, mimetype='application/octet-stream')

# --- Route Stream AES→Chaotic (Hybrid) ---
# @app.route('/stream/<track>/aeschaotic')
# def stream_aes_chaotic(track):
#     if 'logged_in' not in session or not session['logged_in']:
#         return abort(401)

#     # Bước 1: Lấy seed Chaotic từ session
#     chaotic_seed = session.get('chaotic_seed')
#     if chaotic_seed is None:
#         return abort(400, "Chaotic session key not established. Please request key first.")

#     # Bước 2: Lấy blob AES-GCM từ DB
#     blob = get_encrypted_blob(track)
#     if blob is None:
#         return abort(404, f"Track '{track}' chưa được mã hoá trong database.")

#     mime = 'audio/wav' if track.lower().endswith('.wav') else 'audio/mpeg'

#     def generate():
#         # Tách nonce (12 bytes), tag (16 bytes), ciphertext còn lại
#         nonce = blob[:12]
#         tag = blob[12:28]
#         ciphertext = blob[28:]

#         # Khởi tạo AES-GCM decryptor
#         aes_cipher = PyAES.new(aes_key, PyAES.MODE_GCM, nonce=nonce)
#         try:
#             plaintext_all = aes_cipher.decrypt_and_verify(ciphertext, tag)
#         except Exception as e:
#             # Nếu giải mã thất bại, trả 500
#             app.logger.error(f"AES-GCM decrypt failed for {track}: {e}")
#             abort(500, "AES-GCM decrypt failed.")

#         # Khởi tạo ChaoticStreamCipher (để xor mã hoá) với seed từ session
#         scc = ChaoticStreamCipher(seed=chaotic_seed, mu=3.99)

#         # Chia plaintext thành chunk 1024 byte và chaotic-encrypt từng chunk
#         chunk_size = 1024
#         for i in range(0, len(plaintext_all), chunk_size):
#             plain_chunk = plaintext_all[i:i+chunk_size]
#             yield scc.encrypt(plain_chunk)

#     return Response(generate(), mimetype=mime)

if __name__ == '__main__':
    init_db()
    for fname in os.listdir(BASE_PATH):
        if fname.lower().endswith(('.mp3', '.wav')):
            full_path = os.path.join(BASE_PATH, fname)
            encrypt_and_save_to_db(full_path, track_name=fname)
    app.run(port=5000, debug=True, ssl_context=('localhost+2.pem', 'localhost+2-key.pem'))
