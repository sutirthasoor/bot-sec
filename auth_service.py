# auth_service.py
# Standalone Firebase token verification service for Render.
#
# Endpoints:
#   POST /verify
#     Header: Authorization: Bearer <firebase_id_token>
#     Returns 200 {ok: true, user: {...}}  if token valid AND active claim true
#     Returns 401 {ok: false, error: "..."} if token missing/invalid/expired
#     Returns 403 {ok: false, error: "..."} if token valid but active claim false
#
#   GET /health
#     Returns 200 {ok: true} — for Render's health check

import os
import json
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import credentials, auth

app = FastAPI(title="AMT Auth Service", version="1.0.0")

# CORS — allow the panel's origin to call this.
# If the panel runs from a browser (http://localhost:8000, https://panel.yourdomain.com),
# add its origin here. If the panel calls this from a Python backend, CORS doesn't matter.
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------
# Load Firebase service account credentials.
# Two options:
#   (a) LOCAL:  place firebase-service-account.json next to this file
#   (b) RENDER: paste the entire JSON into an env var called
#               FIREBASE_SERVICE_ACCOUNT (single line, no formatting)
# ---------------------------------------------------------------
def _init_firebase():
    if firebase_admin._apps:
        return

    # Option (b): env var on Render
    sa_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT")
    if sa_json:
        cred = credentials.Certificate(json.loads(sa_json))
        firebase_admin.initialize_app(cred)
        print("[auth] Firebase initialized from FIREBASE_SERVICE_ACCOUNT env var")
        return

    # Option (a): file on disk
    path = Path(__file__).parent / "firebase-service-account.json"
    if path.exists():
        cred = credentials.Certificate(str(path))
        firebase_admin.initialize_app(cred)
        print(f"[auth] Firebase initialized from {path}")
        return

    raise RuntimeError(
        "No Firebase credentials found. "
        "Set FIREBASE_SERVICE_ACCOUNT env var OR place "
        "firebase-service-account.json next to auth_service.py"
    )

_init_firebase()


# ---------------------------------------------------------------
# Health check (Render pings this to know the service is up)
# ---------------------------------------------------------------
@app.get("/health")
def health():
    return {"ok": True, "service": "amt-auth", "version": "1.0.0"}


# ---------------------------------------------------------------
# Main endpoint: verify token
# ---------------------------------------------------------------
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

    # Kill-switch: custom claim `active` must be true
    if not decoded.get("active", False):
        raise HTTPException(status_code=403, detail="Access suspended — contact the administrator")

    return {
        "ok": True,
        "user": {
            "uid":   decoded.get("uid"),
            "email": decoded.get("email"),
            "active": True,
        },
    }


# ---------------------------------------------------------------
# Local dev entry point
# ---------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")