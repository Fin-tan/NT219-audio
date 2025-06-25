import os, math
import secrets # Để tạo khóa/seed ngẫu nhiên an toàn
from flask import Flask, render_template, request, session, redirect, url_for, Response, abort, send_from_directory, flash
from werkzeug.utils import secure_filename
from flask import Response, stream_with_context
from flask_session import Session # Để quản lý session
from storage_gcm_db import get_encrypted_blob, kms_client as kms
import sqlite3
import struct, secrets
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
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Tạo thư mục nếu chưa có
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
USERS = {
    'user':   ('password123', 'listener'),
    'author': ('authorpass',  'author'),
}

# ----------------------------------------------------

# --- Route Trang chủ ---
@app.route('/')
def index():
    # Bắt buộc đã login và có role
    if not session.get('logged_in') or session.get('role') is None:
        return redirect(url_for('login'))
    # TODO: thay bằng hàm get_tracks() để load track từ DB
    tracks = get_tracks_with_meta()
    return render_template('index.html',
                           tracks=tracks,
                           username=session.get('username'),
                           role=session.get('role'))
# --- Route Đăng nhập ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        if u in USERS and USERS[u][0] == p:
            session['logged_in'] = True
            session['username']  = u
            session['role']      = USERS[u][1]
            return redirect(url_for('index'))
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

    #  decode base64 DER và load bằng load_der_public_key
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
        return abort(401)

    record = get_encrypted_blob(track)
    if record is None:
        return abort(404, f"Track '{track}' không tồn tại.")
    encrypted_key_blob, data_blob = record

    try:
        kms_resp = kms.decrypt(CiphertextBlob=encrypted_key_blob)
        data_key_plain = kms_resp['Plaintext']
    except Exception as e:
        app.logger.error(f"KMS decrypt failed: {e}")
        return abort(500)

    nonce, tag, ciphertext = data_blob[:12], data_blob[12:28], data_blob[28:]
    aes_cipher = PyAES.new(data_key_plain, PyAES.MODE_GCM, nonce=nonce)
    try:
        plaintext_all = aes_cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        app.logger.error(f"AES-GCM decrypt failed: {e}")
        return abort(500)

    # Định nghĩa hàm parse MP3 frame
    BITRATE_INDEXES = {1:32,2:40,3:48,4:56,5:64,6:80,7:96,8:112,9:128,10:160,11:192,12:224,13:256,14:320}
    SAMPLING_RATES = {0:44100,1:48000,2:32000}
    def get_frame_length(header):
        b1,b2,b3,_ = header
        if b1 != 0xFF or (b2 & 0xE0) != 0xE0:
            return None
        version = (b2 >> 3) & 0x3
        layer = (b2 >> 1) & 0x3
        if version != 3 or layer != 1:
            return None
        bi = (b3 >> 4) & 0xF
        si = (b3 >> 2) & 0x3
        pad = (b3 >> 1) & 0x1
        br = BITRATE_INDEXES.get(bi)
        sr = SAMPLING_RATES.get(si)
        if not br or not sr:
            return None
        return int((144000 * br) / sr + pad)

    def iter_mp3_frames(data):
        i = 0
        while i + 4 <= len(data):
            header = data[i:i+4]
            length = get_frame_length(header)
            if not length or i + length > len(data):
                i += 1
                continue
            yield data[i:i+length]
            i += length
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 2. Tăng lượt xem
    cursor.execute("""
        UPDATE track_metadata
           SET view_count = view_count + 1
         WHERE track_name = ?
    """, (track,))
    conn.commit()

    # 3. Lấy dữ liệu decrypt và trả chunk
    cursor.execute(
        'SELECT encrypted_key, data FROM tracks_gcm WHERE name = ?;',
        (track,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        abort(404)

    def generate():
        data = plaintext_all
        frames = list(iter_mp3_frames(data))
        TARGET_CHUNK = 1024*128
        buf = b''
        chunk_idx = 0
        for frame in frames:
            if len(buf) + len(frame) > TARGET_CHUNK and buf:
                # Đã có đủ buf: encrypt và yield
                seed = secrets.randbelow(1_000_000_000) / 1_000_000_000.0
                scc = ChaoticStreamCipher(seed=seed, mu=3.99)
                encrypted = scc.encrypt(buf)
                packet = struct.pack('!I', 8 + len(encrypted)) + struct.pack('!d', seed) + encrypted
                chunk_idx += 1
                print(f"[DEBUG] Chunk #{chunk_idx} → size={len(packet)} seed={seed:.8f}")
                yield packet
                buf = frame  # bắt đầu nhóm mới với frame hiện tại
            else:
                buf += frame
    # Sau khi hết frames, xử lý phần dư
        if buf:
            seed = secrets.randbelow(1_000_000_000) / 1_000_000_000.0
            scc = ChaoticStreamCipher(seed=seed, mu=3.99)
            encrypted = scc.encrypt(buf)
            packet = struct.pack('!I', 8 + len(encrypted)) + struct.pack('!d', seed) + encrypted
            chunk_idx += 1
            print(f"[DEBUG] Chunk #{chunk_idx} → size={len(packet)} seed={seed:.8f}")
            yield packet


    # Trả về Response stream, định nghĩa đúng MIME type
    return Response(
        stream_with_context(generate()),
        mimetype='audio/mpeg'
    )
def get_tracks_with_meta():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.name, m.author, m.view_count, m.upload_date
        FROM tracks_gcm AS t
        LEFT JOIN track_metadata AS m
          ON t.name = m.track_name
        ORDER BY m.upload_date DESC
    """)
    data = cursor.fetchall()
    conn.close()
    # data: list of tuples (name, author, view_count, upload_date)
    return data
@app.route('/static/<path:filename>')
def serve_static(filename):
    if 'logged_in' not in session or not session['logged_in']:
        return abort(401) # Unauthorized
    return send_from_directory(BASE_PATH, filename)
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        if not f:
            flash('Chưa chọn file!')
            return redirect(request.url)

        filename = secure_filename(f.filename)
        tmp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(tmp_path)

        # 1. Mã hóa và lưu vào tracks_gcm
        encrypt_and_save_to_db(tmp_path, filename)

        # 2. Lấy tác giả:
        author = session.get('username', 'Unknown')

        # 3. Lưu metadata
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO track_metadata(track_name, author)
            VALUES (?, ?)
        """, (filename, author))
        conn.commit()
        conn.close()

        os.remove(tmp_path)
        flash('Upload thành công!')
        return redirect(url_for('index'))
    return render_template('upload.html')
if __name__ == '__main__':
    init_db()
    os.makedirs('encrypted_tmp', exist_ok=True)
    for fname in os.listdir(BASE_PATH):
        if fname.lower().endswith(('.mp3', '.wav')):
            full_path = os.path.join(BASE_PATH, fname)
            encrypt_and_save_to_db(full_path, track_name=fname)
    app.run(port=5000, debug=True, ssl_context=('localhost+2.pem', 'localhost+2-key.pem'))
