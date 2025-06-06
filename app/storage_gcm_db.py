# storage_gcm_db.py

import sqlite3
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# A) Khóa AES-256 chung (không đổi mỗi lần khởi động)
#    Trong production, bạn nên đọc từ ENV hoặc KMS thay vì get_random_bytes
aes_key = get_random_bytes(32)

DB_PATH = os.path.join(os.path.dirname(__file__), 'tracks.db')

def init_db():
    """
    Tạo bảng tracks_gcm (nếu chưa có). 
    BLOB lưu format: [nonce(12 bytes)]‖[tag(16 bytes)]‖[ciphertext].
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tracks_gcm (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT    NOT NULL UNIQUE,
            data BLOB    NOT NULL
        );
    """)
    conn.commit()
    conn.close()

def encrypt_and_save_to_db(input_path, track_name=None):
    """
    Đọc file âm thanh, mã hóa AES-GCM, lưu BLOB vào DB.
    Nếu track_name trùng, sẽ UPDATE blob mới.
    """
    if track_name is None:
        track_name = os.path.basename(input_path)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    blob = nonce + tag + ciphertext

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO tracks_gcm (name, data) VALUES (?, ?);",
            (track_name, blob)
        )
    except sqlite3.IntegrityError:
        cursor.execute(
            "UPDATE tracks_gcm SET data = ? WHERE name = ?;",
            (blob, track_name)
        )
    conn.commit()
    conn.close()

    print(f"[StorageGCM] Đã lưu track '{track_name}' (blob size={len(blob)} bytes)")

def get_encrypted_blob(track_name):
    """
    Lấy về BLOB AES-GCM (nonce‖tag‖ciphertext) từ DB theo tên track.
    Nếu không tồn tại, trả về None.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT data FROM tracks_gcm WHERE name = ?;", (track_name,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None
