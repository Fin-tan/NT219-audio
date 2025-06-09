import os
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import boto3
from boto3.session import Session

# ---------------------------
# Configuration
# ---------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), 'tracks.db')
KMS_KEY_ID= os.getenv('AWS_KMS_KEY_ID')

# Read AWS credentials from environment
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.getenv('AWS_SESSION_TOKEN')
AWS_REGION = os.getenv('AWS_REGION', 'ap-southeast-2')
AWS_PROFILE = os.getenv('AWS_PROFILE')

# ---------------------------
# Initialize KMS client
# ---------------------------
def init_kms_client():
    """
    Create and return a boto3 KMS client.
    Prefer environment credentials; fallback to AWS CLI profile.
    """
    if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
        print(f"[DEBUG] Using ENV creds: {AWS_ACCESS_KEY_ID[:4]}… / {AWS_REGION}")
        return boto3.client(
            'kms',
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            aws_session_token=AWS_SESSION_TOKEN,
        )
    else:
        print(f"[DEBUG] ENV creds missing, falling back to profile: {AWS_PROFILE or 'default'}")
        session = Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
        creds = session.get_credentials()
        print(f"[DEBUG] Profile creds: {creds.access_key[:4] if creds else None}…")
        return session.client('kms')

kms_client = init_kms_client()

# ---------------------------
# Database Helpers
# ---------------------------
def init_db():
    """
    Create the tracks_gcm table if it doesn't exist.
    Columns:
      - name: track name (TEXT, UNIQUE)
      - encrypted_key: data key encrypted by KMS (BLOB)
      - data: AES-GCM payload: nonce||tag||ciphertext (BLOB)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS tracks_gcm (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            encrypted_key BLOB NOT NULL,
            data BLOB NOT NULL
        );
        '''
    )
    conn.commit()
    conn.close()

# ---------------------------
# Encryption Functions
# ---------------------------
def encrypt_and_save_to_db(input_path, track_name=None):
    """
    Encrypt a file with a unique AES-256-GCM data key from KMS,
    then store both the encrypted key and ciphertext in the database.

    Args:
      input_path: path to the plaintext file
      track_name: optional name to store; defaults to filename
    """
    if track_name is None:
        track_name = os.path.basename(input_path)

    # 1) Generate a new data key from KMS
    response = kms_client.generate_data_key(
        KeyId=KMS_KEY_ID,
        KeySpec='AES_256',  # 32-byte key
    )
    plain_key = response['Plaintext']
    encrypted_key = response['CiphertextBlob']

    # 2) Read and encrypt the file
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    nonce = get_random_bytes(12)
    cipher = AES.new(plain_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = nonce + tag + ciphertext

    # 3) Save to database (insert or update)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO tracks_gcm (name, encrypted_key, data) VALUES (?, ?, ?);',
            (track_name, encrypted_key, payload)
        )
    except sqlite3.IntegrityError:
        cursor.execute(
            'UPDATE tracks_gcm SET encrypted_key = ?, data = ? WHERE name = ?;',
            (encrypted_key, payload, track_name)
        )
    conn.commit()
    conn.close()

    print(f"[StorageGCM] Saved track '{track_name}' successfully.")


def get_encrypted_blob(track_name):
    """
    Retrieve the encrypted data key and AES-GCM payload for a given track.

    Returns:
      Tuple(encrypted_key_blob, data_blob) or None if not found.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT encrypted_key, data FROM tracks_gcm WHERE name = ?;',
        (track_name,)
    )
    row = cursor.fetchone()
    conn.close()

    return (row[0], row[1]) if row else None
