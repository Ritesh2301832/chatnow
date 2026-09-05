import json
import asyncio
import random
import string
import os
import hashlib
import secrets
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(DIR, "users.json")

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# In-memory state
waiting_users = {}
active_chats = {}
user_info = {}
user_id_counter = [0]
match_lock = asyncio.Lock()
otp_store = {}  # email -> {"otp": "123456", "verified": False, "user_data": {}}

@app.get("/health")
async def health():
    return JSONResponse({"ok": True})

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(DIR, "index.html"), "r") as f:
        return f.read()

@app.get("/robots.txt")
async def robots():
    with open(os.path.join(DIR, "robots.txt"), "r") as f:
        return HTMLResponse(f.read(), media_type="text/plain")

@app.get("/sitemap.xml")
async def sitemap():
    with open(os.path.join(DIR, "sitemap.xml"), "r") as f:
        return HTMLResponse(f.read(), media_type="application/xml")

@app.post("/api/login")
async def login(request: Request):
    data = await request.json()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    if not email or not password:
        return JSONResponse({"error": "Email and password required"}, status_code=400)
    users = load_users()
    for uname, user in users.items():
        if user.get("email") == email:
            if user.get("password") != hash_pw(password):
                return JSONResponse({"error": "Wrong password"}, status_code=401)
            return JSONResponse({"ok": True, "user": {"username": uname, "display_name": user["display_name"], "email": email}})
    return JSONResponse({"error": "No account with this email"}, status_code=404)

@app.post("/api/google")
async def google_login(request: Request):
    data = await request.json()
    google_id = data.get("google_id", "")
    email = data.get("email", "")
    display_name = data.get("display_name", email.split("@")[0] if email else "User")
    avatar = data.get("avatar", "")
    if not google_id:
        return JSONResponse({"error": "Invalid Google data"}, status_code=400)
    users = load_users()
    username = "g_" + google_id
    if username not in users:
        users[username] = {
            "password": "",
            "email": email,
            "display_name": display_name,
            "avatar": avatar,
            "provider": "google",
            "created_at": str(asyncio.get_event_loop().time()),
        }
        save_users(users)
    return JSONResponse({"ok": True, "user": {"username": username, "display_name": users[username]["display_name"], "email": email, "avatar": avatar}})

@app.post("/api/send-otp")
async def send_otp(request: Request):
    data = await request.json()
    email = data.get("email", "").strip()
    if not email:
        return JSONResponse({"error": "Email required"}, status_code=400)
    otp = "".join(random.choices("0123456789", k=6))
    otp_store[email] = {"otp": otp, "verified": False, "data": data.get("user_data", {})}
    # Production email delivery is not implemented in this original project.
    # Never return the OTP to a public browser. DEV_MODE can be used for local testing.
    if os.getenv("DEV_MODE", "").lower() == "true":
        print(f"[DEV OTP] {email} -> {otp}")
        return JSONResponse({"ok": True, "otp": otp, "message": "Development OTP generated"})
    return JSONResponse({"error": "OTP email delivery is not configured on this server"}, status_code=503)

@app.post("/api/verify-otp")
async def verify_otp(request: Request):
    data = await request.json()
    email = data.get("email", "").strip()
    code = data.get("otp", "").strip()
    stored = otp_store.get(email)
    if not stored:
        return JSONResponse({"error": "No OTP requested for this email"}, status_code=400)
    if stored["otp"] != code:
        return JSONResponse({"error": "Invalid OTP"}, status_code=401)
    stored["verified"] = True
    return JSONResponse({"ok": True, "message": "Email verified"})

@app.post("/api/register")
async def register(request: Request):
    data = await request.json()
    username = str(data.get("username", "")).strip().lower()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    display_name = str(data.get("display_name", "")).strip()

    if not username or not email or not password:
        return JSONResponse({"error": "Username, email and password are required"}, status_code=400)
    if len(password) < 6:
        return JSONResponse({"error": "Password must be at least 6 characters"}, status_code=400)

    verified = otp_store.get(email)
    if not verified or not verified.get("verified"):
        return JSONResponse({"error": "Verify your email with the OTP first"}, status_code=403)

    users = load_users()
    if username in users:
        return JSONResponse({"error": "Username already exists"}, status_code=409)
    if any(str(u.get("email", "")).lower() == email for u in users.values()):
        return JSONResponse({"error": "An account with this email already exists"}, status_code=409)

    users[username] = {
        "password": hash_pw(password),
        "email": email,
        "display_name": display_name or username,
        "avatar": "",
        "provider": "local",
        "created_at": str(asyncio.get_event_loop().time()),
    }
    save_users(users)
    otp_store.pop(email, None)
    return JSONResponse({"ok": True, "user": {
        "username": username,
        "display_name": users[username]["display_name"],
        "email": email,
        "avatar": ""
    }})

@app.post("/api/translate")
async def translate(request: Request):
    data = await request.json()
    text = data.get("text", "")
    src = data.get("source_lang", "auto")
    tgt = data.get("target_lang", "en")
    if not text:
        return JSONResponse({"translated": ""})
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = "https://api.mymemory.translated.net/get"
            params = {"q": text, "langpair": f"{src}|{tgt}"}
            r = await client.get(url, params=params)
            result = r.json()
            translated = result.get("responseData", {}).get("translatedText", text)
            return JSONResponse({"translated": translated})
    except Exception:
        return JSONResponse({"translated": text})

@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    user_id_counter[0] += 1
    uid = user_id_counter[0]
    user_info[websocket] = {"id": uid, "blocked": set()}
    active_chats[websocket] = None
    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            msg_type = msg.get("type")

            if msg_type == "register":
                user_info[websocket].update({
                    "gender": msg.get("gender", "any"),
                    "orientation": msg.get("orientation", "any"),
                    "country": msg.get("country", "Unknown"),
                    "lang": msg.get("lang", "en"),
                    "lat": msg.get("lat", 0),
                    "lon": msg.get("lon", 0),
                    "city": msg.get("city", "Unknown"),
                    "name": (msg.get("name") or f"Stranger_{uid:04d}"),
                    "sub_pref": msg.get("sub_pref", "any"),
                    "username": msg.get("username", ""),
                    "blocked": user_info[websocket].get("blocked", set()),
                })
                await websocket.send_text(json.dumps({
                    "type": "registered",
                    "user": user_info[websocket]
                }))

            elif msg_type == "find":
                partner = await find_match(websocket)
                if partner:
                    active_chats[websocket] = partner
                    active_chats[partner] = websocket
                    await websocket.send_text(json.dumps({
                        "type": "matched",
                        "partner": _safe_info(partner)
                    }))
                    await partner.send_text(json.dumps({
                        "type": "matched",
                        "partner": _safe_info(websocket)
                    }))
                else:
                    waiting_users[websocket] = user_info[websocket]
                    await websocket.send_text(json.dumps({"type": "waiting"}))

            elif msg_type == "message":
                partner = active_chats.get(websocket)
                if partner:
                    await partner.send_text(json.dumps({
                        "type": "message",
                        "text": msg.get("text", ""),
                        "from": user_info[websocket].get("name", "Stranger"),
                    }))

            elif msg_type == "image":
                partner = active_chats.get(websocket)
                if partner:
                    await partner.send_text(json.dumps({
                        "type": "image",
                        "data": msg.get("data", ""),
                        "from": user_info[websocket].get("name", "Stranger"),
                    }))

            elif msg_type == "typing":
                partner = active_chats.get(websocket)
                if partner:
                    await partner.send_text(json.dumps({"type": "typing"}))

            elif msg_type == "stop_typing":
                partner = active_chats.get(websocket)
                if partner:
                    await partner.send_text(json.dumps({"type": "stop_typing"}))

            elif msg_type == "report":
                partner = active_chats.get(websocket)
                if partner:
                    reports = user_info[partner].setdefault("reports", [])
                    reports.append({
                        "from": user_info[websocket].get("name", "Stranger"),
                        "reason": str(msg.get("reason", "User report"))[:200],
                    })
                    await websocket.send_text(json.dumps({"type": "reported"}))

            elif msg_type == "block":
                partner = active_chats.get(websocket)
                if partner:
                    user_info[websocket].setdefault("blocked", set()).add(user_info[partner].get("name", "Stranger"))
                    active_chats[partner] = None
                    try:
                        await partner.send_text(json.dumps({
                            "type": "partner_left",
                            "message": "Stranger left the chat."
                        }))
                    except Exception:
                        pass
                    active_chats[websocket] = None
                    await websocket.send_text(json.dumps({"type": "blocked"}))

            elif msg_type == "disconnect":
                await disconnect_user(websocket)
                break

            elif msg_type == "next":
                # Leave the current partner, but keep this user's identity/preferences
                # so they can immediately search for the next stranger.
                partner = active_chats.get(websocket)
                if partner:
                    active_chats[partner] = None
                    try:
                        await partner.send_text(json.dumps({
                            "type": "partner_left",
                            "message": "Stranger left the chat."
                        }))
                    except Exception:
                        pass
                active_chats[websocket] = None
                waiting_users.pop(websocket, None)

                partner = await find_match(websocket)
                if partner:
                    active_chats[websocket] = partner
                    active_chats[partner] = websocket
                    await websocket.send_text(json.dumps({
                        "type": "matched",
                        "partner": _safe_info(partner)
                    }))
                    await partner.send_text(json.dumps({
                        "type": "matched",
                        "partner": _safe_info(websocket)
                    }))
                else:
                    waiting_users[websocket] = user_info[websocket]
                    await websocket.send_text(json.dumps({"type": "waiting"}))

    except WebSocketDisconnect:
        await disconnect_user(websocket)
    except Exception:
        await disconnect_user(websocket)

def _safe_info(ws):
    info = user_info.get(ws, {})
    return {
        "name": info.get("name", "Stranger"),
        "gender": info.get("gender", "unknown"),
        "orientation": info.get("orientation", "any"),
        "country": info.get("country", "Unknown"),
        "lang": info.get("lang", "en"),
        "city": info.get("city", "Unknown"),
        "sub_pref": info.get("sub_pref", "any"),
    }

async def find_match(ws):
    """Strictly match male users with female users, and vice versa."""
    me = user_info.get(ws, {})
    my_gender = me.get("gender", "").lower()
    if my_gender not in {"male", "female"}:
        return None

    async with match_lock:
        # Remove stale/self entries before searching.
        waiting_users.pop(ws, None)
        candidates = list(waiting_users.keys())
        random.shuffle(candidates)

        for candidate in candidates:
            if candidate == ws or candidate not in user_info:
                waiting_users.pop(candidate, None)
                continue

            them = user_info.get(candidate, {})
            their_gender = str(them.get("gender", "")).lower()

            # STRICT RULE:
            # male <-> female only. No same-gender or "any" matches.
            if {my_gender, their_gender} != {"male", "female"}:
                continue

            if them.get("name", "") in me.get("blocked", set()):
                continue
            if me.get("name", "") in them.get("blocked", set()):
                continue

            waiting_users.pop(candidate, None)
            return candidate

    return None


def is_compatible(g1, o1, g2, o2, sp1="any", sp2="any"):
    """Single strict compatibility rule used by matchmaking."""
    return {
        str(g1).lower(),
        str(g2).lower(),
    } == {"male", "female"}


async def disconnect_user(ws):
    partner = active_chats.get(ws)
    if partner and partner in active_chats:
        active_chats[partner] = None
        try:
            await partner.send_text(json.dumps({"type": "partner_left", "message": "Stranger left the chat."}))
        except Exception:
            pass
    active_chats.pop(ws, None)
    waiting_users.pop(ws, None)
    user_info.pop(ws, None)
