#!/usr/bin/env python3
"""Agent-only gateway for the private skill registry.

Exposes the registry's typed actions to external agents over HTTPS (via tunnel).
Every mutating or data endpoint requires a valid Ed25519 agent signature.
No human UI. Private keys never touch this server.

Endpoints:
  GET  /protocol                  - agent protocol doc (public)
  GET  /v1/status                 - health (public, minimal)
  POST /v1/agents/register        - self-signed agent registration (trust N0)
  POST /v1/call                   - signed action call -> queued
  GET  /v1/result/{id}            - signed result poll (requesting agent only)
  POST /v1/bridge/pending         - bridge token: list queued requests
  POST /v1/bridge/result          - bridge token: store execution result
"""
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "gateway.db")
TOKEN_PATH = os.path.join(BASE, "bridge_token")
PROTOCOL_PATH = os.path.join(BASE, "PROTOCOL.md")

VERSION = "1.0.0"
MAX_PARAMS_BYTES = 300_000
RATE_PER_HOUR = 60
TS_WINDOW = 300          # seconds
NONCE_TTL = 900          # seconds

# Registry actions allowed through the gateway (admin seeding excluded).
ALLOWLIST = {
    "attestexecution", "getskill", "prepareattestation", "preparepublication",
    "prepareregistration", "preparerevocation", "protocolmanifest",
    "publishskill", "registeragent", "registrystatus", "revoke", "searchskills",
}

AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS agents(
      agent_id TEXT PRIMARY KEY, display_name TEXT, pubkey_hex TEXT,
      trust_level TEXT DEFAULT 'N0', created_at INTEGER);
    CREATE TABLE IF NOT EXISTS requests(
      id TEXT PRIMARY KEY, agent_id TEXT, action TEXT, params_json TEXT,
      status TEXT DEFAULT 'queued', created_at INTEGER, done_at INTEGER,
      result_json TEXT, error TEXT);
    CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, seen_at INTEGER);
    CREATE TABLE IF NOT EXISTS audit(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, agent_id TEXT,
      action TEXT, ok INTEGER, detail TEXT);
    CREATE TABLE IF NOT EXISTS rate(
      agent_id TEXT PRIMARY KEY, window_start INTEGER, count INTEGER);
    """)
    con.commit()
    con.close()
    os.chmod(DB_PATH, 0o600)


def audit(agent_id, action, ok, detail=""):
    con = db()
    con.execute("INSERT INTO audit(ts,agent_id,action,ok,detail) VALUES(?,?,?,?,?)",
                (int(time.time()), agent_id, action, 1 if ok else 0, detail[:500]))
    con.commit()
    con.close()


def canonical(params):
    return json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def check_rate(agent_id):
    now = int(time.time())
    con = db()
    row = con.execute("SELECT window_start,count FROM rate WHERE agent_id=?", (agent_id,)).fetchone()
    if row is None or now - row["window_start"] >= 3600:
        con.execute("INSERT OR REPLACE INTO rate(agent_id,window_start,count) VALUES(?,?,1)",
                    (agent_id, now))
        con.commit()
        con.close()
        return True
    if row["count"] >= RATE_PER_HOUR:
        con.close()
        return False
    con.execute("UPDATE rate SET count=count+1 WHERE agent_id=?", (agent_id,))
    con.commit()
    con.close()
    return True


def check_nonce(nonce):
    now = int(time.time())
    con = db()
    con.execute("DELETE FROM nonces WHERE seen_at < ?", (now - NONCE_TTL,))
    exists = con.execute("SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone()
    if exists:
        con.close()
        return False
    con.execute("INSERT INTO nonces(nonce,seen_at) VALUES(?,?)", (nonce, now))
    con.commit()
    con.close()
    return True


def get_agent(agent_id):
    con = db()
    row = con.execute("SELECT agent_id,display_name,pubkey_hex,trust_level FROM agents WHERE agent_id=?",
                      (agent_id,)).fetchone()
    con.close()
    return row


def verify_sig(pubkey_hex, message: bytes, signature_b64: str) -> bool:
    import base64
    try:
        vk = VerifyKey(bytes.fromhex(pubkey_hex))
        sig = base64.b64decode(signature_b64)
        vk.verify(message, sig)
        return True
    except (BadSignatureError, ValueError, Exception):
        return False


def verify_envelope(body):
    """Returns (agent_row, error)."""
    for f in ("agent_id", "timestamp", "nonce", "action", "params", "signature_b64"):
        if f not in body:
            return None, f"missing field: {f}"
    agent_id = body["agent_id"]
    if not AGENT_ID_RE.match(agent_id or ""):
        return None, "bad agent_id"
    agent = get_agent(agent_id)
    if agent is None:
        return None, "unknown agent (register first)"
    try:
        ts = int(body["timestamp"])
    except (ValueError, TypeError):
        return None, "bad timestamp"
    if abs(int(time.time()) - ts) > TS_WINDOW:
        return None, "timestamp outside window"
    if not check_nonce(str(body["nonce"])):
        return None, "nonce reused"
    action = body["action"]
    if action not in ALLOWLIST:
        return None, "action not allowed"
    params = body["params"]
    if not isinstance(params, dict):
        return None, "params must be an object"
    if len(canonical(params).encode()) > MAX_PARAMS_BYTES:
        return None, "params too large"
    msg = f"v1.call.{agent_id}.{ts}.{body['nonce']}.{action}.{hashlib.sha256(canonical(params).encode()).hexdigest()}"
    if not verify_sig(agent["pubkey_hex"], msg.encode(), body["signature_b64"]):
        return None, "bad signature"
    if not check_rate(agent_id):
        return None, "rate limit exceeded"
    return agent, None


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGateway/" + VERSION

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self, max_bytes=400_000):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if n <= 0 or n > max_bytes:
            return None
        try:
            return json.loads(self.rfile.read(n))
        except (json.JSONDecodeError, ValueError):
            return None

    def _bridge_ok(self):
        try:
            with open(TOKEN_PATH) as f:
                token = f.read().strip()
        except OSError:
            return False
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {token}" and bool(token)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/protocol":
            try:
                with open(PROTOCOL_PATH, "rb") as f:
                    data = f.read()
            except OSError:
                return self._send(500, {"ok": False, "error": "protocol unavailable"})
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/v1/status":
            con = db()
            depth = con.execute("SELECT COUNT(*) c FROM requests WHERE status='queued'").fetchone()["c"]
            nagents = con.execute("SELECT COUNT(*) c FROM agents").fetchone()["c"]
            con.close()
            return self._send(200, {"ok": True, "version": VERSION, "queue_depth": depth, "agents": nagents})
        m = re.fullmatch(r"/v1/result/([0-9a-f-]{36})", path)
        if m:
            # Signed poll: agent_id, timestamp, nonce, signature_b64 as query? No - use headers+body is awkward
            # for GET. Require the signature over a fixed message passed as JSON body (some clients allow it);
            # simpler and safe: request id is an unguessable capability, but we additionally require the
            # caller's agent_id to match the request owner via a signed token in the Authorization header:
            # "Agent <agent_id>.<timestamp>.<nonce>.<signature_b64>".
            req_id = m.group(1)
            auth = self.headers.get("Authorization", "")
            mm = re.fullmatch(r"Agent ([a-z0-9][a-z0-9_-]{1,63})\.(\d+)\.([A-Za-z0-9_-]{8,64})\.([A-Za-z0-9+/=]+)", auth)
            if not mm:
                return self._send(401, {"ok": False, "error": "missing/invalid Agent authorization"})
            agent_id, ts_s, nonce, sig_b64 = mm.groups()
            agent = get_agent(agent_id)
            if agent is None:
                return self._send(401, {"ok": False, "error": "unknown agent"})
            ts = int(ts_s)
            if abs(int(time.time()) - ts) > TS_WINDOW:
                return self._send(401, {"ok": False, "error": "timestamp outside window"})
            if not check_nonce("r" + nonce):
                return self._send(401, {"ok": False, "error": "nonce reused"})
            msg = f"v1.result.{req_id}.{agent_id}.{ts}.{nonce}"
            if not verify_sig(agent["pubkey_hex"], msg.encode(), sig_b64):
                audit(agent_id, "result", False, "bad signature")
                return self._send(401, {"ok": False, "error": "bad signature"})
            if not check_rate(agent_id):
                return self._send(429, {"ok": False, "error": "rate limit exceeded"})
            con = db()
            row = con.execute("SELECT status,agent_id,result_json,error FROM requests WHERE id=?", (req_id,)).fetchone()
            con.close()
            if row is None:
                return self._send(404, {"ok": False, "error": "unknown request"})
            if row["agent_id"] != agent_id:
                audit(agent_id, "result", False, "cross-agent read attempt")
                return self._send(403, {"ok": False, "error": "not your request"})
            out = {"ok": True, "status": row["status"]}
            if row["status"] == "done":
                out["result"] = json.loads(row["result_json"]) if row["result_json"] else None
            elif row["status"] == "failed":
                out["error"] = row["error"]
            audit(agent_id, "result", True, req_id)
            return self._send(200, out)
        return self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/v1/agents/register":
            body = self._read_json()
            if not body:
                return self._send(400, {"ok": False, "error": "bad json"})
            agent_id = body.get("agent_id", "")
            display = body.get("display_name", "")
            pubkey = body.get("pubkey_hex", "")
            sig = body.get("signature_b64", "")
            if not AGENT_ID_RE.match(agent_id or ""):
                return self._send(400, {"ok": False, "error": "bad agent_id"})
            if not (2 <= len(display) <= 120):
                return self._send(400, {"ok": False, "error": "bad display_name"})
            if not re.fullmatch(r"[0-9a-f]{64}", pubkey or ""):
                return self._send(400, {"ok": False, "error": "pubkey_hex must be 64 hex chars (ed25519)"})
            msg = f"v1.register.{agent_id}.{pubkey}"
            if not verify_sig(pubkey, msg.encode(), sig or ""):
                audit(agent_id, "register", False, "bad proof signature")
                return self._send(401, {"ok": False, "error": "proof signature invalid (sign the register payload)"})
            con = db()
            con.execute("INSERT OR REPLACE INTO agents(agent_id,display_name,pubkey_hex,trust_level,created_at)"
                        " VALUES(?,?,?,'N0',?)", (agent_id, display, pubkey, int(time.time())))
            con.commit()
            con.close()
            audit(agent_id, "register", True, "N0")
            return self._send(200, {"ok": True, "agent_id": agent_id, "trust_level": "N0"})
        if path == "/v1/call":
            body = self._read_json()
            if not body:
                return self._send(400, {"ok": False, "error": "bad json"})
            agent, err = verify_envelope(body)
            if err:
                audit(body.get("agent_id", "?"), body.get("action", "?"), False, err)
                code = 429 if err == "rate limit exceeded" else 401
                return self._send(code, {"ok": False, "error": err})
            req_id = str(uuid.uuid4())
            con = db()
            con.execute("INSERT INTO requests(id,agent_id,action,params_json,status,created_at)"
                        " VALUES(?,?,?,?, 'queued',?)",
                        (req_id, agent["agent_id"], body["action"], canonical(body["params"]), int(time.time())))
            con.commit()
            con.close()
            audit(agent["agent_id"], body["action"], True, req_id)
            return self._send(200, {"ok": True, "request_id": req_id, "status": "queued"})
        if path == "/v1/bridge/pending":
            if not self._bridge_ok():
                return self._send(401, {"ok": False, "error": "bad bridge token"})
            con = db()
            rows = con.execute("SELECT id,agent_id,action,params_json,created_at FROM requests"
                               " WHERE status='queued' ORDER BY created_at LIMIT 25").fetchall()
            con.close()
            return self._send(200, {"ok": True, "pending": [
                {"request_id": r["id"], "agent_id": r["agent_id"], "action": r["action"],
                 "params": json.loads(r["params_json"]), "created_at": r["created_at"]} for r in rows]})
        if path == "/v1/bridge/result":
            if not self._bridge_ok():
                return self._send(401, {"ok": False, "error": "bad bridge token"})
            body = self._read_json()
            if not body or "request_id" not in body or "ok" not in body:
                return self._send(400, {"ok": False, "error": "bad json"})
            con = db()
            if body["ok"]:
                con.execute("UPDATE requests SET status='done', done_at=?, result_json=? WHERE id=?",
                            (int(time.time()), json.dumps(body.get("result")), body["request_id"]))
            else:
                con.execute("UPDATE requests SET status='failed', done_at=?, error=? WHERE id=?",
                            (int(time.time()), str(body.get("error", ""))[:500], body["request_id"]))
            con.commit()
            con.close()
            audit("bridge", "bridge_result", True, body["request_id"])
            return self._send(200, {"ok": True})
        return self._send(404, {"ok": False, "error": "not found"})


if __name__ == "__main__":
    init_db()
    if not os.path.exists(TOKEN_PATH):
        import secrets
        with open(TOKEN_PATH, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(TOKEN_PATH, 0o600)
        print("bridge token generated")
    # NOTE: the bridge token is pre-shared with the operator's bridge only.
    # For external hosting, inject it via the BRIDGE_TOKEN env var instead.
    env_token = os.environ.get("BRIDGE_TOKEN")
    if env_token and len(env_token) >= 32:
        with open(TOKEN_PATH, "w") as f:
            f.write(env_token.strip())
        os.chmod(TOKEN_PATH, 0o600)
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"gateway {VERSION} listening on {host}:{port}", flush=True)
    srv.serve_forever()
