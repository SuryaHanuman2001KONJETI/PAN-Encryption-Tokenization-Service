"""
PAN Encryption & Tokenization Service (Educational)

- AES-GCM for encrypting PANs (never store plain PAN)
- Tokenization: random token → encrypted PAN
- Masking: first 6 + last 4
- SQLite storage
- Admin-only decrypt using X-ADMIN-API-KEY
"""

import os
import sqlite3
import binascii
import secrets
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# ---------------------- Load environment variables ----------------------
load_dotenv()

MASTER_KEY_HEX = os.getenv("MASTER_KEY_HEX")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "admin-placeholder")
DATABASE = os.getenv("DATABASE", "./tokens.db")

if not MASTER_KEY_HEX:
    raise SystemExit("MASTER_KEY_HEX must be set in .env")

try:
    MASTER_KEY = binascii.unhexlify(MASTER_KEY_HEX)
except Exception as e:
    raise SystemExit("Invalid MASTER_KEY_HEX (must be hex). Error: " + str(e))

if len(MASTER_KEY) not in (16, 24, 32):
    raise SystemExit("MASTER_KEY must be 16, 24, or 32 bytes for AES-GCM")


# ---------------------- Database Setup ----------------------
def init_db():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            pan_length INTEGER NOT NULL,
            first6 TEXT,
            last4 TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


db_conn = init_db()

# ---------------------- FastAPI App ----------------------
app = FastAPI(title="PAN Encryption & Tokenization Service")

@app.get("/")
def root():
    return {
        "service": "PAN Encryption & Tokenization Service",
        "endpoints": ["/encrypt", "/decrypt", "/token/{token}", "/health", "/docs"]
    }


# ---------------------- Models ----------------------
class EncryptRequest(BaseModel):
    pan: str = Field(..., min_length=12, max_length=19, description="Card PAN")


class EncryptResponse(BaseModel):
    token: str
    masked_pan: str


class DecryptRequest(BaseModel):
    token: str


class DecryptResponse(BaseModel):
    pan: str
    masked_pan: str


class TokenMetadata(BaseModel):
    token: str
    masked_pan: str
    created_at: str


# ---------------------- Crypto Helpers ----------------------
def encrypt_pan_bytes(pan_bytes: bytes):
    aes = AESGCM(MASTER_KEY)
    nonce = secrets.token_bytes(12)
    ciphertext = aes.encrypt(nonce, pan_bytes, None)
    return nonce, ciphertext


def decrypt_pan_bytes(nonce: bytes, ciphertext: bytes):
    aes = AESGCM(MASTER_KEY)
    return aes.decrypt(nonce, ciphertext, None)


# ---------------------- PAN Masking ----------------------
def mask_pan(first6: str, last4: str, length: int):
    middle = length - len(first6) - len(last4)
    return first6 + ("*" * middle) + last4


# ---------------------- Database Helpers ----------------------
def save_token(token, nonce, ciphertext, pan_length, first6, last4):
    cur = db_conn.cursor()
    cur.execute("""
        INSERT INTO tokens (token, ciphertext, nonce, pan_length, first6, last4, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        token,
        sqlite3.Binary(ciphertext),
        sqlite3.Binary(nonce),
        pan_length,
        first6,
        last4,
        datetime.utcnow().isoformat()
    ))
    db_conn.commit()


def get_token_record(token: str):
    cur = db_conn.cursor()
    cur.execute("""
        SELECT token, ciphertext, nonce, pan_length, first6, last4, created_at
        FROM tokens WHERE token = ?
    """, (token,))
    row = cur.fetchone()
    if not row:
        return None
    return {
        "token": row[0],
        "ciphertext": row[1],
        "nonce": row[2],
        "pan_length": row[3],
        "first6": row[4],
        "last4": row[5],
        "created_at": row[6]
    }


# ---------------------- Admin Auth ----------------------
def require_admin(api_key: Optional[str] = Header(None, alias="X-ADMIN-API-KEY")):
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin API key.")
    return True


# ---------------------- API Endpoints ----------------------
@app.post("/encrypt", response_model=EncryptResponse)
def encrypt(req: EncryptRequest):
    pan = req.pan

    if not pan.isdigit():
        raise HTTPException(status_code=400, detail="PAN must contain only digits")

    pan_bytes = pan.encode("utf-8")
    nonce, ciphertext = encrypt_pan_bytes(pan_bytes)

    token = secrets.token_urlsafe(24)
    first6 = pan[:6]
    last4 = pan[-4:]
    pan_length = len(pan)

    save_token(token, nonce, ciphertext, pan_length, first6, last4)
    masked = mask_pan(first6, last4, pan_length)

    return EncryptResponse(token=token, masked_pan=masked)


@app.post("/decrypt", response_model=DecryptResponse)
def decrypt(req: DecryptRequest, _=Depends(require_admin)):
    record = get_token_record(req.token)
    if not record:
        raise HTTPException(status_code=404, detail="Token not found")

    try:
        pan_bytes = decrypt_pan_bytes(record["nonce"], record["ciphertext"])
        pan = pan_bytes.decode("utf-8")
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")

    masked = mask_pan(record["first6"], record["last4"], record["pan_length"])
    return DecryptResponse(pan=pan, masked_pan=masked)


@app.get("/token/{token}", response_model=TokenMetadata)
def get_metadata(token: str):
    record = get_token_record(token)
    if not record:
        raise HTTPException(status_code=404, detail="Token not found")

    masked = mask_pan(record["first6"], record["last4"], record["pan_length"])

    return TokenMetadata(
        token=token,
        masked_pan=masked,
        created_at=record["created_at"]
    )


@app.get("/health")
def health():
    return {"status": "ok"}
