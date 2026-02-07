import os
import json
import time
import hmac
import hashlib
import secrets
from typing import Dict, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException

# ================== MASTER ACCESS ==================
MASTER_KEY = "THR-9F4A-7C2E-B8D1-6A3F"
MASTER_PASSWORD = "mP@9Xr!Q6K#Z2Y8W^5L"

MASTER_COMBINED = f"{MASTER_KEY}:{MASTER_PASSWORD}"
MASTER_SALT = b"static_salt_chat_app"

def verify_master(key: str, password: str) -> bool:
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        f"{key}:{password}".encode(),
        MASTER_SALT,
        600_000
    )
    real = hashlib.pbkdf2_hmac(
        "sha256",
        MASTER_COMBINED.encode(),
        MASTER_SALT,
        600_000
    )
    return hmac.compare_digest(derived, real)

# ================== DATA ==================
users_public_keys: Dict[str, str] = {}
active_sockets: Dict[str, WebSocket] = {}
offline_messages: Dict[str, List[dict]] = {}

# ================== APP ==================
app = FastAPI()

@app.get("/")
async def root():
    return {"status": "secure chat backend running"}

# ================== REGISTER ==================
@app.post("/register")
async def register(data: dict):
    username = data.get("username")
    public_key = data.get("public_key")
    master_key = data.get("master_key")
    master_password = data.get("master_password")

    if not verify_master(master_key, master_password):
        raise HTTPException(status_code=401, detail="Invalid master access")

    if not username or username in users_public_keys:
        raise HTTPException(status_code=400, detail="Invalid username")

    users_public_keys[username] = public_key
    return {"status": "registered"}

# ================== PUBLIC KEY ==================
@app.get("/public_key/{username}")
async def get_public_key(username: str):
    if username not in users_public_keys:
        raise HTTPException(status_code=404, detail="Not found")
    return {"public_key": users_public_keys[username]}

# ================== WEBSOCKET ==================
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    try:
        init = json.loads(await ws.receive_text())
        username = init.get("username")

        if username not in users_public_keys:
            await ws.close()
            return

        active_sockets[username] = ws

        # send offline messages
        if username in offline_messages:
            for msg in offline_messages[username]:
                await ws.send_json(msg)
            del offline_messages[username]

        while True:
            data = json.loads(await ws.receive_text())
            to = data.get("to")

            message = {
                "from": username,
                "to": to,
                "ciphertext": data.get("ciphertext"),
                "timestamp": int(time.time())
            }

            if to in active_sockets:
                await active_sockets[to].send_json(message)
            else:
                offline_messages.setdefault(to, []).append(message)

    except WebSocketDisconnect:
        active_sockets.pop(username, None)
