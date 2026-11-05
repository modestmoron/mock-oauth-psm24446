#!/usr/bin/env python3
"""Mock OAuth 2 server (Salesforce-like) for PSM-24446.

Endpoints:
  GET  /authorize   auto-approves and redirects to redirect_uri with ?code=...&state=...
  POST /token       grant_type=authorization_code | refresh_token
  GET  /api/data    needs "Authorization: Bearer <access token>"; 401 if missing/expired
  GET  /log         recent events (secrets masked)
  GET  /            health + settings

Behaviour (env vars):
  CLIENT_ID / CLIENT_SECRET   expected client credentials (body or Basic auth)
  ACCESS_TTL                  access token lifetime in seconds (default 120)
  ROTATE                      1 = every refresh returns a new refresh token and the old one stops working
                              0 = refresh tokens are reused and not returned on refresh (default 1)
Any rejected refresh answers like Salesforce:
  400 {"error":"unknown_error","error_description":"retry your request"}
and the log records the real reason (old refresh token, wrong secret, missing secret, ...).
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

CLIENT_ID = os.environ.get("CLIENT_ID", "psm24446-client")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "psm24446-secret")
ACCESS_TTL = int(os.environ.get("ACCESS_TTL", "120"))
ROTATE = os.environ.get("ROTATE", "1") == "1"
BOOT_ID = uuid.uuid4().hex[:8]
BOOT_AT = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

codes = {}            # code -> issued_at
access_tokens = {}    # token -> expires_at
refresh_tokens = {}   # token -> {"status": "active"|"rotated", "issued_at": ts}
events = []


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def mask(value):
    if not value:
        return None
    return f"...{value[-6:]}"


def secret_fingerprint(value):
    if value is None:
        return None
    return hashlib.sha256(value.encode()).hexdigest()[:10]


def log(event, **fields):
    entry = {"time": now_iso(), "boot_id": BOOT_ID, "event": event, **fields}
    events.append(entry)
    del events[:-500]
    print(json.dumps(entry), flush=True)


def new_access_token():
    token = "AT_" + secrets.token_urlsafe(18)
    access_tokens[token] = time.time() + ACCESS_TTL
    return token


def new_refresh_token():
    token = "RT_" + secrets.token_urlsafe(18)
    refresh_tokens[token] = {"status": "active", "issued_at": now_iso()}
    return token


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _send(self, status, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _client_credentials(self, form):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("basic "):
            try:
                cid, csecret = base64.b64decode(auth[6:]).decode().split(":", 1)
                return cid, csecret, "basic_header"
            except Exception:
                return None, None, "basic_header_invalid"
        return form.get("client_id"), form.get("client_secret"), "body"

    def do_GET(self):
        url = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}

        if url.path == "/":
            self._send(200, {"ok": True, "boot_id": BOOT_ID, "boot_at": BOOT_AT,
                             "access_ttl_sec": ACCESS_TTL, "rotate": ROTATE})
        elif url.path == "/authorize":
            code = "CODE_" + secrets.token_urlsafe(12)
            codes[code] = time.time()
            log("authorize", client_id=query.get("client_id"), redirect_uri=query.get("redirect_uri"),
                scope=query.get("scope"), has_code_challenge="code_challenge" in query)
            target = query.get("redirect_uri", "")
            sep = "&" if "?" in target else "?"
            location = target + sep + urlencode({"code": code, "state": query.get("state", "")})
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif url.path == "/api/data":
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.lower().startswith("bearer ") else None
            expires_at = access_tokens.get(token)
            if not token or expires_at is None or expires_at < time.time():
                reason = "missing" if not token else ("unknown" if expires_at is None else "expired")
                log("api_401", access_token=mask(token), reason=reason)
                self._send(401, [{"message": "Session expired or invalid", "errorCode": "INVALID_SESSION_ID"}])
                return
            log("api_200", access_token=mask(token), expires_in=int(expires_at - time.time()))
            self._send(200, {"ok": True, "time": now_iso(), "boot_id": BOOT_ID})
        elif url.path == "/log":
            self._send(200, {"boot_id": BOOT_ID, "boot_at": BOOT_AT, "events": events[-int(query.get("n", "100")):]})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        url = urlparse(self.path)
        if url.path != "/token":
            self._send(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode()
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        grant = form.get("grant_type")
        cid, csecret, cred_source = self._client_credentials(form)
        base = {"grant_type": grant, "client_id": cid, "cred_source": cred_source,
                "client_secret_present": bool(csecret),
                "client_secret_fp": secret_fingerprint(csecret),
                "expected_secret_fp": secret_fingerprint(CLIENT_SECRET),
                "form_keys": sorted(form.keys()), "content_type": self.headers.get("Content-Type")}

        def reject(reason, **extra):
            log("token_400", reason=reason, **base, **extra)
            self._send(400, {"error": "unknown_error", "error_description": "retry your request"})

        if cid != CLIENT_ID:
            reject("wrong_client_id")
            return
        if not csecret:
            reject("missing_client_secret")
            return
        if csecret != CLIENT_SECRET:
            reject("wrong_client_secret")
            return

        if grant == "authorization_code":
            code = form.get("code")
            if code not in codes:
                reject("unknown_code")
                return
            codes.pop(code)
            access, refresh = new_access_token(), new_refresh_token()
            log("token_200_auth_code", **base, new_access=mask(access), new_refresh=mask(refresh))
            self._send(200, {"access_token": access, "refresh_token": refresh, "token_type": "Bearer",
                             "instance_url": f"https://{self.headers.get('Host')}", "issued_at": str(int(time.time() * 1000))})
        elif grant == "refresh_token":
            sent = form.get("refresh_token")
            info = refresh_tokens.get(sent)
            if info is None:
                reject("unknown_refresh_token", refresh_token=mask(sent))
                return
            if info["status"] != "active":
                reject("reused_rotated_refresh_token", refresh_token=mask(sent), issued_at=info["issued_at"])
                return
            access = new_access_token()
            body = {"access_token": access, "token_type": "Bearer", "issued_at": str(int(time.time() * 1000))}
            extra = {}
            if ROTATE:
                info["status"] = "rotated"
                refresh = new_refresh_token()
                body["refresh_token"] = refresh
                extra["new_refresh"] = mask(refresh)
            log("token_200_refresh", **base, refresh_token=mask(sent), new_access=mask(access), **extra)
            self._send(200, body)
        else:
            reject("unsupported_grant_type")


def main():
    port = int(os.environ.get("PORT", sys.argv[1] if len(sys.argv) > 1 else "8080"))
    log("boot", port=port, access_ttl_sec=ACCESS_TTL, rotate=ROTATE)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
