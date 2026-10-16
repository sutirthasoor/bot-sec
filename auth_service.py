# auth_service.py
# Firebase auth proxy for Render.
# The browser talks to this service — no Firebase SDK, no firebaseConfig in the frontend.
#
# Endpoints:
#   GET  /health    → {ok, service, version}
#   POST /login     {email, password} → {ok, idToken, refreshToken, expiresIn, user}
#   POST /refresh   {refresh_token}   → {ok, idToken, refreshToken, expiresIn}
#   POST /verify    Header: Bearer <idToken> → {ok, user} | 401/403

import os
import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import credentials, auth

# ============================================================
# Firebase service account — hardcoded
# ============================================================
SERVICE_ACCOUNT = {
    "type": "service_account",
    "project_id": "my-bot-7690b",
    "private_key_id": "e07963f0bf1eacecf4754402e73dab82e162b7fe",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLrGHV7ILHSEUw\nHhENwiTRvhdeBO6H33rJe+t8MbUIQElDSEN1x7PGjriJVu1gwOZ3ZhoW5vTHBVjR\nUG959rnBRL+CvqjWNe8ypHvTJhs+KDE/U/5wl1szuEBL1602s3aAEhldbXWPQBwT\nIFv8IOa1zLe/EpdHfS64+3UDzIroYGXVg0xuraRt2NUPrEkeRSYSbwAI0YRoOxEX\ncvefzrf/fMkEUWNkyaStVgGb2ss3MsNJ8O6kfhyvBgmS348q5vJxq44UYrrShLSz\nEM1Ey6M3pXgmFuk7e8cwOYIP4ZDJC+bRs1OgMQZyHEbzOllsxaqIFloTxjjVKnNn\njudykq6xAgMBAAECggEAEViRjoQRkUJU7iepYSgXNavAVrgJzpWYYf+FSzL6jYTY\nGHxXjnjfFTqDeeLm3ZYgKqwN7cRmtWp9qXn1vIfoQw8FVm/BdljqkcATcaStrkoD\nA7c2FMW3NTzscOkh7eYz4e1orp3LZNNbcL+RRfRRYctZHNNLAgIl0AhOa2/opqik\nH63d1kcXuukg43Hy6FNveZ7LIojeLAMAdTYfuif0RCFn1+qjkvHzGcXUno3AGf2B\nHO390GZFPUF8ZoYcuZStALbikw1anO1VUqJ+jUL8Qsmr34w8ySn6/3sOAwifNSrD\njg3muUnaoNdSnU2hE9bFO9IJnZrNmWb6/c0LxvPUnwKBgQDxNAnCyYWUcD9i5x4O\nBQydQWwVByubeLA+E2ggZzPP9k2jGAf2T0cdgHmpZahFht6yDK3rMJEGQpb358F3\nOex+6xatyouX4/JaO764jv8W2knlgw6m0ZF/cPlS8aXHMf1guaHV5CyixR6/V+qa\n58b/C0M6hgz/pmWFqlRNp2yXGwKBgQDYKvU8rPrWoqGM6vE9LD1KadjNLbmZjCqB\n6k7RD+/OvKwQmoJG9zbkqZiPUyUH0my9CF+rHsuZZGWi7Mv7eQVXL4iMQ+GQN52O\nXV50w6v1qPh460QNmpEKeN4CNh+dYpZp/JLjhl+eya6BRXxDMBTL+rbCGHLJfXLJ\nstyMoVByIwKBgBnFL43KLiVv4LXWb5Wb4H8ksEGG5JfVyy62sBdWL2j2rdDRDni4\ne6ahRV5d6B6VjFGFnUdVhwkeMDcIYdk1LRlaUK/8xfFSf2A4peXeEU8Fv4Nv/y6/\nkUYGcfz0qHuh0ap16t6JZGN3oBNdd0lZnh89us8T52uhAZPIYP1y990lAoGBAL9j\n4XeUTA7HNTPYPDkGN0nwR1T6fA6YDHa0Jo5xhshLQij9NAVzEjYIdpvHaMzxIPeJ\nN3MBtBAe1OIYuE3xi6ny2vodi9OteiE3R88oA9NghIZC/yDwTiSweRgKJZmqVTSH\nvOIX8gdb19Z62BeAtZkYZMGa9d6x5HTymNUmalxzAoGBAO2C5An9fz/mnj5o1K6M\navDWJ7nrBRvpOANjWX0AbSlmWH4xI+SVamHbcYkO/pZgzzms0dVJ6sTiuZTJ4p91\nCMoofIkVenpZEQByQEnM3xQk1b8NdL+HYRerZ3ktTSdx4iuRLp8jr6Thf+ZnxfeU\nAUK6GLhW7+ZiPHitW4sT4Hac\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-fbsvc@my-bot-7690b.iam.gserviceaccount.com",
    "client_id": "115787578068720894313",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40my-bot-7690b.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com",
}

# ============================================================
# Firebase Web API Key — from your firebaseConfig
# ============================================================
FIREBASE_WEB_API_KEY = "AIzaSyC4MJwGGoKGUUI7dlgC0IDn9dSQt95kUdo"

IDENTITY_BASE    = "https://identitytoolkit.googleapis.com/v1"
SECURETOKEN_BASE = "https://securetoken.googleapis.com/v1"

# ============================================================
# FastAPI app
# ============================================================
app = FastAPI(title="AMT Auth Service", version="2.0.0")

ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ============================================================
# Firebase Admin init
# ============================================================
def _init_firebase():
    if firebase_admin._apps:
        return
    cred = credentials.Certificate(SERVICE_ACCOUNT)
    firebase_admin.initialize_app(cred)
    print("[auth] Firebase Admin initialized")

_init_firebase()


# ============================================================
# Endpoints
# ============================================================
@app.get("/health")
def health():
    return {"ok": True, "service": "amt-auth", "version": "2.0.0"}


@app.post("/login")
async def login(body: dict):
    """body = {"email": "...", "password": "..."}"""
    email    = (body.get("email") or "").strip()
    password = body.get("password") or ""
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{IDENTITY_BASE}/accounts:signInWithPassword",
            params={"key": FIREBASE_WEB_API_KEY},
            json={
                "email":             email,
                "password":          password,
                "returnSecureToken": True,
            },
        )

    if r.status_code != 200:
        try:
            err = r.json().get("error", {}).get("message", "LOGIN_FAILED")
        except Exception:
            err = "LOGIN_FAILED"
        friendly = {
            "EMAIL_NOT_FOUND": "Email not registered",
            "INVALID_PASSWORD": "Incorrect password",
            "INVALID_LOGIN_CREDENTIALS": "Incorrect email or password",
            "USER_DISABLED": "Account disabled",
            "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts — try again later",
        }.get(err, err)
        raise HTTPException(status_code=401, detail=friendly)

    data = r.json()

    # Verify token and enforce active claim before handing it back
    try:
        decoded = auth.verify_id_token(data["idToken"], check_revoked=True)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token error: {e}")

    if not decoded.get("active", False):
        raise HTTPException(status_code=403, detail="Access suspended — contact the administrator")

    return {
        "ok":           True,
        "idToken":      data["idToken"],
        "refreshToken": data["refreshToken"],
        "expiresIn":    int(data.get("expiresIn", 3600)),
        "user": {
            "uid":   decoded.get("uid"),
            "email": decoded.get("email"),
        },
    }


@app.post("/refresh")
async def refresh(body: dict):
    """body = {"refresh_token": "..."}"""
    rt = body.get("refresh_token")
    if not rt:
        raise HTTPException(status_code=400, detail="refresh_token required")

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{SECURETOKEN_BASE}/token",
            params={"key": FIREBASE_WEB_API_KEY},
            data={
                "grant_type":    "refresh_token",
                "refresh_token": rt,
            },
        )

    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    data = r.json()

    # Re-check active claim on refresh
    try:
        decoded = auth.verify_id_token(data["id_token"], check_revoked=True)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token error: {e}")

    if not decoded.get("active", False):
        raise HTTPException(status_code=403, detail="Access suspended — contact the administrator")

    return {
        "ok":           True,
        "idToken":      data["id_token"],
        "refreshToken": data["refresh_token"],
        "expiresIn":    int(data.get("expires_in", 3600)),
    }


@app.post("/verify")
def verify(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = authorization.split(" ", 1)[1].strip()
    try:
        decoded = auth.verify_id_token(token, check_revoked=True)
    except auth.ExpiredIdTokenError:
        raise HTTPException(status_code=401, detail="Token expired")
    except auth.RevokedIdTokenError:
        raise HTTPException(status_code=401, detail="Token revoked")
    except auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Auth error: {e}")

    if not decoded.get("active", False):
        raise HTTPException(status_code=403, detail="Access suspended — contact the administrator")

    return {
        "ok": True,
        "user": {
            "uid":    decoded.get("uid"),
            "email":  decoded.get("email"),
            "active": True,
        },
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")