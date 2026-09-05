import json
import asyncio
import random
import os
import hashlib
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


# =========================================================
# USER STORAGE
# =========================================================

def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# =========================================================
# IN-MEMORY CHAT STATE
# =========================================================

waiting_users = {}
active_chats = {}
user_info = {}

user_id_counter = 0

match_lock = asyncio.Lock()

otp_store = {}


# =========================================================
# BASIC ROUTES
# =========================================================

@app.get("/health")
async def health():
    return JSONResponse({
        "ok": True,
        "waiting": len(waiting_users),
        "active": sum(
            1 for ws, partner in active_chats.items()
            if partner is not None
        ) // 2
    })


@app.get("/", response_class=HTMLResponse)
async def index():
    with open(
        os.path.join(DIR, "index.html"),
        "r",
        encoding="utf-8"
    ) as f:
        return f.read()


@app.get("/robots.txt")
async def robots():
    with open(
        os.path.join(DIR, "robots.txt"),
        "r",
        encoding="utf-8"
    ) as f:
        return HTMLResponse(
            f.read(),
            media_type="text/plain"
        )


@app.get("/sitemap.xml")
async def sitemap():
    with open(
        os.path.join(DIR, "sitemap.xml"),
        "r",
        encoding="utf-8"
    ) as f:
        return HTMLResponse(
            f.read(),
            media_type="application/xml"
        )


# =========================================================
# LOGIN
# =========================================================

@app.post("/api/login")
async def login(request: Request):

    data = await request.json()

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return JSONResponse(
            {"error": "Email and password required"},
            status_code=400
        )

    users = load_users()

    for username, user in users.items():

        if str(user.get("email", "")).lower() == email:

            if user.get("password") != hash_pw(password):
                return JSONResponse(
                    {"error": "Wrong password"},
                    status_code=401
                )

            return JSONResponse({
                "ok": True,
                "user": {
                    "username": username,
                    "display_name": user.get(
                        "display_name",
                        username
                    ),
                    "email": email
                }
            })

    return JSONResponse(
        {"error": "No account with this email"},
        status_code=404
    )


# =========================================================
# GOOGLE LOGIN
# =========================================================

@app.post("/api/google")
async def google_login(request: Request):

    data = await request.json()

    google_id = data.get("google_id", "")
    email = data.get("email", "")
    display_name = data.get(
        "display_name",
        email.split("@")[0] if email else "User"
    )
    avatar = data.get("avatar", "")

    if not google_id:
        return JSONResponse(
            {"error": "Invalid Google data"},
            status_code=400
        )

    users = load_users()

    username = "g_" + str(google_id)

    if username not in users:

        users[username] = {
            "password": "",
            "email": email,
            "display_name": display_name,
            "avatar": avatar,
            "provider": "google",
            "created_at": str(
                asyncio.get_event_loop().time()
            )
        }

        save_users(users)

    return JSONResponse({
        "ok": True,
        "user": {
            "username": username,
            "display_name": users[username].get(
                "display_name",
                display_name
            ),
            "email": email,
            "avatar": users[username].get(
                "avatar",
                avatar
            )
        }
    })


# =========================================================
# OTP
# =========================================================

@app.post("/api/send-otp")
async def send_otp(request: Request):

    data = await request.json()

    email = str(data.get("email", "")).strip().lower()

    if not email:
        return JSONResponse(
            {"error": "Email required"},
            status_code=400
        )

    otp = "".join(
        random.choices(
            "0123456789",
            k=6
        )
    )

    otp_store[email] = {
        "otp": otp,
        "verified": False,
        "data": data.get(
            "user_data",
            {}
        )
    }

    if os.getenv("DEV_MODE", "").lower() == "true":

        print(
            f"[DEV OTP] {email} -> {otp}"
        )

        return JSONResponse({
            "ok": True,
            "otp": otp,
            "message": "Development OTP generated"
        })

    return JSONResponse(
        {
            "error":
            "OTP email delivery is not configured on this server"
        },
        status_code=503
    )


@app.post("/api/verify-otp")
async def verify_otp(request: Request):

    data = await request.json()

    email = str(
        data.get("email", "")
    ).strip().lower()

    code = str(
        data.get("otp", "")
    ).strip()

    stored = otp_store.get(email)

    if not stored:
        return JSONResponse(
            {"error": "No OTP requested for this email"},
            status_code=400
        )

    if stored["otp"] != code:
        return JSONResponse(
            {"error": "Invalid OTP"},
            status_code=401
        )

    stored["verified"] = True

    return JSONResponse({
        "ok": True,
        "message": "Email verified"
    })


# =========================================================
# REGISTER
# =========================================================

@app.post("/api/register")
async def register(request: Request):

    data = await request.json()

    username = str(
        data.get("username", "")
    ).strip().lower()

    email = str(
        data.get("email", "")
    ).strip().lower()

    password = str(
        data.get("password", "")
    )

    display_name = str(
        data.get("display_name", "")
    ).strip()

    if not username or not email or not password:
        return JSONResponse(
            {
                "error":
                "Username, email and password are required"
            },
            status_code=400
        )

    if len(password) < 6:
        return JSONResponse(
            {
                "error":
                "Password must be at least 6 characters"
            },
            status_code=400
        )

    verified = otp_store.get(email)

    if not verified or not verified.get("verified"):
        return JSONResponse(
            {
                "error":
                "Verify your email with the OTP first"
            },
            status_code=403
        )

    users = load_users()

    if username in users:
        return JSONResponse(
            {"error": "Username already exists"},
            status_code=409
        )

    if any(
        str(u.get("email", "")).lower() == email
        for u in users.values()
    ):
        return JSONResponse(
            {
                "error":
                "An account with this email already exists"
            },
            status_code=409
        )

    users[username] = {
        "password": hash_pw(password),
        "email": email,
        "display_name": display_name or username,
        "avatar": "",
        "provider": "local",
        "created_at": str(
            asyncio.get_event_loop().time()
        )
    }

    save_users(users)

    otp_store.pop(email, None)

    return JSONResponse({
        "ok": True,
        "user": {
            "username": username,
            "display_name": users[username]["display_name"],
            "email": email,
            "avatar": ""
        }
    })


# =========================================================
# TRANSLATION
# =========================================================

@app.post("/api/translate")
async def translate(request: Request):

    data = await request.json()

    text = data.get("text", "")
    src = data.get(
        "source_lang",
        "auto"
    )
    tgt = data.get(
        "target_lang",
        "en"
    )

    if not text:
        return JSONResponse({
            "translated": ""
        })

    try:

        async with httpx.AsyncClient(
            timeout=10
        ) as client:

            url = (
                "https://api.mymemory.translated.net/get"
            )

            params = {
                "q": text,
                "langpair":
                    f"{src}|{tgt}"
            }

            response = await client.get(
                url,
                params=params
            )

            result = response.json()

            translated = (
                result
                .get("responseData", {})
                .get(
                    "translatedText",
                    text
                )
            )

            return JSONResponse({
                "translated": translated
            })

    except Exception:
        return JSONResponse({
            "translated": text
        })


# =========================================================
# SAFE USER INFO
# =========================================================

def _safe_info(ws):

    info = user_info.get(ws, {})

    return {
        "name": info.get(
            "name",
            "Stranger"
        ),

        "gender": info.get(
            "gender",
            "unknown"
        ),

        "orientation": info.get(
            "orientation",
            "any"
        ),

        "country": info.get(
            "country",
            "Unknown"
        ),

        "lang": info.get(
            "lang",
            "en"
        ),

        "city": info.get(
            "city",
            "Unknown"
        ),

        "sub_pref": info.get(
            "sub_pref",
            "any"
        )
    }


# =========================================================
# STRICT MATCHING
# =========================================================

def is_compatible(
    g1,
    o1,
    g2,
    o2,
    sp1="any",
    sp2="any"
):

    g1 = str(g1).lower().strip()
    g2 = str(g2).lower().strip()

    # ONLY:
    # male <-> female
    return (
        (g1 == "male" and g2 == "female")
        or
        (g1 == "female" and g2 == "male")
    )


async def find_match(ws):

    me = user_info.get(ws)

    if not me:
        return None

    my_gender = str(
        me.get("gender", "")
    ).lower().strip()

    # Only male/female users can enter matching.
    if my_gender not in {
        "male",
        "female"
    }:
        return None

    async with match_lock:

        # Remove ourselves from queue.
        waiting_users.pop(
            ws,
            None
        )

        candidates = list(
            waiting_users.keys()
        )

        random.shuffle(
            candidates
        )

        for candidate in candidates:

            # Invalid websocket.
            if candidate == ws:
                continue

            if candidate not in user_info:
                waiting_users.pop(
                    candidate,
                    None
                )
                continue

            # Already matched.
            if active_chats.get(candidate):
                waiting_users.pop(
                    candidate,
                    None
                )
                continue

            them = user_info.get(
                candidate,
                {}
            )

            their_gender = str(
                them.get(
                    "gender",
                    ""
                )
            ).lower().strip()

            # STRICT OPPOSITE GENDER.
            if not is_compatible(
                my_gender,
                me.get("orientation"),
                their_gender,
                them.get("orientation"),
                me.get("sub_pref"),
                them.get("sub_pref")
            ):
                continue

            # Block checks.
            my_blocked = me.get(
                "blocked",
                set()
            )

            their_blocked = them.get(
                "blocked",
                set()
            )

            my_name = me.get(
                "name",
                ""
            )

            their_name = them.get(
                "name",
                ""
            )

            if their_name in my_blocked:
                continue

            if my_name in their_blocked:
                continue

            # Remove candidate from queue.
            waiting_users.pop(
                candidate,
                None
            )

            return candidate

    return None


# =========================================================
# MATCH USERS
# =========================================================

async def match_users(ws):

    partner = await find_match(ws)

    if not partner:
        waiting_users[ws] = user_info[ws]

        try:
            await ws.send_text(
                json.dumps({
                    "type": "waiting"
                })
            )
        except Exception:
            pass

        return None

    active_chats[ws] = partner
    active_chats[partner] = ws

    try:

        await ws.send_text(
            json.dumps({
                "type": "matched",
                "partner":
                    _safe_info(partner)
            })
        )

        await partner.send_text(
            json.dumps({
                "type": "matched",
                "partner":
                    _safe_info(ws)
            })
        )

    except Exception:

        active_chats[ws] = None
        active_chats[partner] = None

        return None

    return partner


# =========================================================
# WEBSOCKET
# =========================================================

@app.websocket("/ws/chat")
async def websocket_endpoint(
    websocket: WebSocket
):

    global user_id_counter

    await websocket.accept()

    user_id_counter += 1

    uid = user_id_counter

    user_info[websocket] = {
        "id": uid,
        "blocked": set()
    }

    active_chats[websocket] = None

    try:

        while True:

            raw = await websocket.receive_text()

            try:
                msg = json.loads(raw)
            except Exception:
                continue

            msg_type = msg.get(
                "type"
            )


            # =================================================
            # REGISTER
            # =================================================

            if msg_type == "register":

                user_info[websocket].update({

                    "gender": str(
                        msg.get(
                            "gender",
                            ""
                        )
                    ).lower().strip(),

                    "orientation":
                        msg.get(
                            "orientation",
                            "straight"
                        ),

                    "country":
                        msg.get(
                            "country",
                            "Unknown"
                        ),

                    "lang":
                        msg.get(
                            "lang",
                            "en"
                        ),

                    "lat":
                        msg.get(
                            "lat",
                            0
                        ),

                    "lon":
                        msg.get(
                            "lon",
                            0
                        ),

                    "city":
                        msg.get(
                            "city",
                            "Unknown"
                        ),

                    "name":
                        msg.get(
                            "name"
                        ) or
                        f"Stranger_{uid:04d}",

                    "sub_pref":
                        msg.get(
                            "sub_pref",
                            "any"
                        ),

                    "username":
                        msg.get(
                            "username",
                            ""
                        )
                })

                await websocket.send_text(
                    json.dumps({
                        "type":
                            "registered",

                        "user":
                            _safe_info(
                                websocket
                            )
                    })
                )


            # =================================================
            # FIND
            # =================================================

            elif msg_type == "find":

                # Don't allow a user to create
                # duplicate queue entries.
                if active_chats.get(websocket):
                    continue

                await match_users(
                    websocket
                )


            # =================================================
            # MESSAGE
            # =================================================

            elif msg_type == "message":

                partner = active_chats.get(
                    websocket
                )

                if partner:

                    text = str(
                        msg.get(
                            "text",
                            ""
                        )
                    ).strip()

                    if not text:
                        continue

                    await partner.send_text(
                        json.dumps({
                            "type":
                                "message",

                            "text":
                                text,

                            "from":
                                user_info[
                                    websocket
                                ].get(
                                    "name",
                                    "Stranger"
                                )
                        })
                    )


            # =================================================
            # IMAGE
            # =================================================

            elif msg_type == "image":

                partner = active_chats.get(
                    websocket
                )

                if partner:

                    await partner.send_text(
                        json.dumps({
                            "type":
                                "image",

                            "data":
                                msg.get(
                                    "data",
                                    ""
                                ),

                            "from":
                                user_info[
                                    websocket
                                ].get(
                                    "name",
                                    "Stranger"
                                )
                        })
                    )


            # =================================================
            # TYPING
            # =================================================

            elif msg_type == "typing":

                partner = active_chats.get(
                    websocket
                )

                if partner:

                    await partner.send_text(
                        json.dumps({
                            "type":
                                "typing"
                        })
                    )


            # =================================================
            # STOP TYPING
            # =================================================

            elif msg_type == "stop_typing":

                partner = active_chats.get(
                    websocket
                )

                if partner:

                    await partner.send_text(
                        json.dumps({
                            "type":
                                "stop_typing"
                        })
                    )


            # =================================================
            # REPORT
            # =================================================

            elif msg_type == "report":

                partner = active_chats.get(
                    websocket
                )

                if partner:

                    reports = user_info[
                        partner
                    ].setdefault(
                        "reports",
                        []
                    )

                    reports.append({
                        "from":
                            user_info[
                                websocket
                            ].get(
                                "name",
                                "Stranger"
                            ),

                        "reason":
                            str(
                                msg.get(
                                    "reason",
                                    "User report"
                                )
                            )[:200]
                    })

                    await websocket.send_text(
                        json.dumps({
                            "type":
                                "reported"
                        })
                    )


            # =================================================
            # BLOCK
            # =================================================

            elif msg_type == "block":

                partner = active_chats.get(
                    websocket
                )

                if partner:

                    blocked_name = user_info[
                        partner
                    ].get(
                        "name",
                        "Stranger"
                    )

                    user_info[
                        websocket
                    ].setdefault(
                        "blocked",
                        set()
                    ).add(
                        blocked_name
                    )

                    active_chats[
                        partner
                    ] = None

                    try:

                        await partner.send_text(
                            json.dumps({
                                "type":
                                    "partner_left",

                                "message":
                                    "Stranger left the chat."
                            })
                        )

                    except Exception:
                        pass

                    active_chats[
                        websocket
                    ] = None

                    await websocket.send_text(
                        json.dumps({
                            "type":
                                "blocked"
                        })
                    )


            # =================================================
            # NEXT
            # =================================================

            elif msg_type == "next":

                partner = active_chats.get(
                    websocket
                )

                if partner:

                    active_chats[
                        partner
                    ] = None

                    try:

                        await partner.send_text(
                            json.dumps({
                                "type":
                                    "partner_left",

                                "message":
                                    "Stranger left the chat."
                            })
                        )

                    except Exception:
                        pass

                active_chats[
                    websocket
                ] = None

                waiting_users.pop(
                    websocket,
                    None
                )

                # Immediately search again.
                await match_users(
                    websocket
                )


            # =================================================
            # DISCONNECT
            # =================================================

            elif msg_type == "disconnect":

                await disconnect_user(
                    websocket
                )

                break


    except WebSocketDisconnect:

        await disconnect_user(
            websocket
        )

    except Exception as e:

        print(
            f"[WebSocket error] {e}"
        )

        await disconnect_user(
            websocket
        )


# =========================================================
# DISCONNECT CLEANUP
# =========================================================

async def disconnect_user(ws):

    partner = active_chats.get(
        ws
    )

    if partner and partner in active_chats:

        active_chats[
            partner
        ] = None

        try:

            await partner.send_text(
                json.dumps({
                    "type":
                        "partner_left",

                    "message":
                        "Stranger left the chat."
                })
            )

        except Exception:
            pass

    active_chats.pop(
        ws,
        None
    )

    waiting_users.pop(
        ws,
        None
    )

    user_info.pop(
        ws,
        None
    )
