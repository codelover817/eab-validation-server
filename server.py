"""
validation_server/server.py — Central license validation server.

Deploy this to Railway or Render (free tier).
Your WHOP_API_KEY lives ONLY here — never inside the distributed .exe.

Environment variables to set on Railway/Render:
  WHOP_API_KEY       — your Whop bearer token
  CLIENT_SECRET      — run setup_validation_server.py to generate this
  PORT               — set automatically by Railway/Render
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

WHOP_API_KEY   = os.environ.get("WHOP_API_KEY", "")
CLIENT_SECRET  = os.environ.get("CLIENT_SECRET", "")
MAX_CLOCK_SKEW = 300   # 5 minutes

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

_ACTIVE_STATUSES = {"trialing", "active", "past_due", "completed"}

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ValidateRequest(BaseModel):
    key: str
    ts: int
    sig: str


class ValidateResponse(BaseModel):
    valid: bool
    plan: str = "member"
    expires_at: int | None = None
    membership_id: str = ""
    sig: str = ""


# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------

def _sign_request(ts: int, key: str) -> str:
    return hmac.new(
        CLIENT_SECRET.encode(),
        f"REQ:{ts}:{key}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _sign_response(valid: bool, expires_at: int | None, membership_id: str) -> str:
    payload = f"RESP:{valid}:{expires_at}:{membership_id}"
    return hmac.new(
        CLIENT_SECRET.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Startup guard
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def _startup_guard():
    if not WHOP_API_KEY:
        raise RuntimeError("WHOP_API_KEY not set — server will not start without it.")
    if not CLIENT_SECRET:
        raise RuntimeError("CLIENT_SECRET not set — run setup_validation_server.py to generate one.")


# ---------------------------------------------------------------------------
# Validation endpoint
# ---------------------------------------------------------------------------

@app.post("/v1/validate", response_model=ValidateResponse)
async def validate(body: ValidateRequest, request: Request):
    # 1. Reject missing config
    if not WHOP_API_KEY or not CLIENT_SECRET:
        raise HTTPException(503, "Server not configured.")

    # 2. Replay / clock-skew check
    if abs(time.time() - body.ts) > MAX_CLOCK_SKEW:
        raise HTTPException(422, "Timestamp expired.")

    # 3. Verify request signature — proves request came from legitimate .exe
    expected_sig = _sign_request(body.ts, body.key)
    if not hmac.compare_digest(expected_sig, body.sig):
        raise HTTPException(403, "Invalid signature.")

    # 4. Sanitise key
    if len(body.key) < 8 or len(body.key) > 200:
        return ValidateResponse(valid=False, sig=_sign_response(False, None, ""))

    # 5. Ask Whop
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://api.whop.com/api/v1/memberships/{body.key}",
                headers={"Authorization": f"Bearer {WHOP_API_KEY}"},
            )
    except Exception:
        raise HTTPException(503, "Upstream validation unavailable. Try again.")

    if resp.status_code == 404:
        sig = _sign_response(False, None, "")
        return ValidateResponse(valid=False, sig=sig)

    if resp.status_code != 200:
        raise HTTPException(502, "Upstream error.")

    data = resp.json()
    status = data.get("status", "")
    valid = status in _ACTIVE_STATUSES

    expires_at: int | None = None
    renewal_end = data.get("renewal_period_end")
    if renewal_end:
        try:
            expires_at = int(float(renewal_end))
        except (ValueError, TypeError):
            pass

    membership_id = str(data.get("id") or "")
    sig = _sign_response(valid, expires_at, membership_id)

    return ValidateResponse(
        valid=valid,
        plan="member",
        expires_at=expires_at,
        membership_id=membership_id,
        sig=sig,
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"ok": True, "ts": int(time.time())}


# ---------------------------------------------------------------------------
# Entry point (Railway/Render calls uvicorn directly via Procfile)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
