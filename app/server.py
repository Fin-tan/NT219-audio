import os
import secrets # Để tạo khóa/seed ngẫu nhiên an toàn
from flask import Flask, render_template, request, session, redirect, url_for, Response, abort, send_from_directory
from flask_session import Session # Để quản lý session

# Giả định ChaoticStreamCipher và aes_key đã được định nghĩa
from stream_cipher import ChaoticStreamCipher
# from storage import aes_key # Nếu bạn muốn dùng aes_key từ file khác

app = Flask(__name__, template_folder='templates')

# --- Cấu hình Session ---
app.config['SECRET_KEY'] = 'your_super_secret_key_here_change_this_in_production' # Rất quan trọng! Thay đổi trong sản phẩm!
app.config['SESSION_TYPE'] = 'filesystem'  # Lưu session trên filesystem (đơn giản cho demo)
# app.config['SESSION_COOKIE_SECURE'] = True # Chỉ gửi cookie qua HTTPS (nên dùng trong sản phẩm)
# app.config['SESSION_COOKIE_HTTPONLY'] = True # Ngăn JS truy cập cookie (nên dùng)
Session(app)
# ------------------------

# --- Cấu hình đường dẫn file ---
BASE_PATH = os.path.join(os.path.dirname(__file__), 'static')
ENCRYPTED_DIR = os.path.join(os.path.dirname(__file__), 'encrypted')

if not os.path.exists(ENCRYPTED_DIR):
    os.makedirs(ENCRYPTED_DIR)

# --- Helper function để lấy danh sách tracks ---
def get_tracks():
    return [f for f in os.listdir(BASE_PATH) if f.lower().endswith(('.mp3', '.wav'))]

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

# --- Route mới để CẤP KHÓA THEO SESSION ---
@app.route('/get_chaotic_session_key')
def get_chaotic_session_key():
    if 'logged_in' not in session or not session['logged_in']:
        return abort(401) # Unauthorized

    # Tạo một seed ngẫu nhiên cho phiên hiện tại
    # secrets.randbelow(N) trả về một số nguyên ngẫu nhiên < N
    # Để có float từ 0 đến 1, chúng ta chia cho một số lớn
    random_seed = secrets.randbelow(1_000_000_000) / 1_000_000_000.0
    
    # Lưu seed này vào session của người dùng
    session['chaotic_seed'] = random_seed
    
    return {'seed': random_seed, 'mu': 3.99} # Trả về seed và mu cho client

# --- Route Streaming Chaotic (đã chỉnh sửa để dùng khóa từ session) ---
@app.route('/stream/<track>/chaotic')
def stream_chaotic(track):
    if 'logged_in' not in session or not session['logged_in']:
        return abort(401) # Unauthorized
    
    # Lấy seed từ session. Nếu không có, có thể do chưa gọi get_chaotic_session_key
    chaotic_seed = session.get('chaotic_seed')
    if chaotic_seed is None:
        return abort(400, "Chaotic session key not established. Please request key first.")

    src_path = os.path.join(BASE_PATH, track)
    if not os.path.isfile(src_path): return abort(404)
    mime = 'audio/wav' if track.lower().endswith('.wav') else 'audio/mpeg'

    def generate():
        # KHỞI TẠO CIPHER VỚI SEED TỪ SESSION
        scc = ChaoticStreamCipher(seed=chaotic_seed, mu=3.99) 
        
        with open(src_path, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk: break
                yield scc.encrypt(chunk)
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


if __name__ == '__main__':
    app.run(port=5000, debug=True , ssl_context=('localhost+2.pem', 'localhost+2-key.pem'))