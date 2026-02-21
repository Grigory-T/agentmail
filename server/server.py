#!/usr/bin/env python3
"""Mail server — HTTPS + SQLite. Stores and delivers encrypted mail."""

import http.server
import socketserver
import ssl
import sqlite3
import json
import os
import time
import logging

import nacl.signing
import nacl.exceptions

MAX_BODY       = 64 * 1024  # 64 KB per JSON request
MAX_CIPHERTEXT = 32 * 1024  # 32 KB decoded ciphertext
SENDER_LIMIT   = 1_000      # max messages per sender
GLOBAL_LIMIT   = 1_000_000  # max total messages
TS_WINDOW      = 60         # seconds, inbox auth timestamp tolerance
RATE_WINDOW    = 60         # seconds, per-IP send window
RATE_LIMIT     = 20         # max sends per IP per window

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("mailserver")

DIR       = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(DIR, "mailbox.db")
CONF_PATH = os.path.join(DIR, "server.conf")

# in-memory IP rate limiter: {ip: [timestamp, ...]}
_rate_log = {}


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS mail (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            date      TEXT NOT NULL,
            sender    TEXT NOT NULL,
            recipient TEXT NOT NULL,
            body      BLOB NOT NULL,
            sig       BLOB NOT NULL DEFAULT X''
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_recipient ON mail(recipient, id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_sender    ON mail(sender, id)")
    db.commit()
    db.close()


def enforce_limits(db, sender):
    # per-sender: delete oldest by this sender if over limit
    (count,) = db.execute("SELECT COUNT(*) FROM mail WHERE sender = ?", (sender,)).fetchone()
    if count >= SENDER_LIMIT:
        db.execute("""
            DELETE FROM mail WHERE id IN (
                SELECT id FROM mail WHERE sender = ? ORDER BY id ASC LIMIT ?
            )
        """, (sender, count - SENDER_LIMIT + 1))

    # global: delete oldest overall if over limit
    (total,) = db.execute("SELECT COUNT(*) FROM mail").fetchone()
    if total >= GLOBAL_LIMIT:
        db.execute("""
            DELETE FROM mail WHERE id IN (
                SELECT id FROM mail ORDER BY id ASC LIMIT ?
            )
        """, (total - GLOBAL_LIMIT + 1,))


def verify_inbox_auth(to, ts_str, after_str, sig_hex):
    """Return True if sig is a valid Ed25519 signature of 'ts|to|after' by the key 'to'."""
    try:
        ts = int(ts_str)
        if abs(time.time() - ts) > TS_WINDOW:
            return False
        payload = f"{ts_str}|{to}|{after_str}".encode()
        vk = nacl.signing.VerifyKey(bytes.fromhex(to))
        vk.verify(payload, bytes.fromhex(sig_hex))
        return True
    except Exception:
        return False


def check_rate(ip):
    """Return True if ip is within rate limit, False if exceeded."""
    now = time.time()
    times = _rate_log.get(ip, [])
    cutoff = now - RATE_WINDOW
    times = [t for t in times if t > cutoff]
    if len(times) >= RATE_LIMIT:
        _rate_log[ip] = times
        return False
    times.append(now)
    _rate_log[ip] = times
    return True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info(fmt, *args)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        if length > MAX_BODY:
            raise ValueError(f"body too large: {length} bytes")
        return json.loads(self.rfile.read(length))

    def _respond(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            if self.path != "/send":
                return self._respond(404, {"error": "not found"})
            if not check_rate(self.client_address[0]):
                return self._respond(429, {"error": "rate limit exceeded"})
            data = self._read_body()
            for field in ("from", "to", "body", "sig"):
                if field not in data:
                    return self._respond(400, {"error": f"missing: {field}"})
                if not isinstance(data[field], str):
                    return self._respond(400, {"error": f"invalid type: {field} must be a string"})
            # validate from and to are 32-byte hex keys
            try:
                from_bytes = bytes.fromhex(data["from"])
                to_bytes   = bytes.fromhex(data["to"])
                if len(from_bytes) != 32:
                    return self._respond(400, {"error": "invalid from key"})
                if len(to_bytes) != 32:
                    return self._respond(400, {"error": "invalid to key"})
            except ValueError:
                return self._respond(400, {"error": "invalid key encoding"})
            # decode body and sig, check sizes
            try:
                body_bytes = bytes.fromhex(data["body"])
                sig_bytes  = bytes.fromhex(data["sig"])
            except ValueError:
                return self._respond(400, {"error": "invalid hex encoding"})
            if len(body_bytes) > MAX_CIPHERTEXT:
                return self._respond(400, {"error": "ciphertext too large"})
            if len(sig_bytes) != 64:
                return self._respond(400, {"error": "invalid signature length"})
            # verify sender signature
            try:
                vk = nacl.signing.VerifyKey(from_bytes)
                vk.verify(body_bytes, sig_bytes)
            except Exception:
                return self._respond(403, {"error": "invalid signature"})
            db = sqlite3.connect(DB_PATH)
            enforce_limits(db, data["from"])
            cur = db.execute(
                "INSERT INTO mail (date, sender, recipient, body, sig) VALUES (datetime('now'), ?, ?, ?, ?)",
                (data["from"], data["to"], body_bytes, sig_bytes),
            )
            db.commit()
            mail_id = cur.lastrowid
            db.close()
            self._respond(200, {"ok": True, "id": mail_id})
        except Exception as e:
            log.error("POST error: %s", e)
            self._respond(500, {"error": str(e)})

    def do_GET(self):
        try:
            path = self.path.split("?")[0]
            if path == "/health":
                return self._respond(200, {"ok": True})
            if path != "/inbox":
                return self._respond(404, {"error": "not found"})

            params = {}
            if "?" in self.path:
                for part in self.path.split("?", 1)[1].split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        params[k] = v

            to     = params.get("to", "")
            ts     = params.get("ts", "")
            sig    = params.get("sig", "")
            after  = int(params.get("after", "0"))

            if not to:
                return self._respond(400, {"error": "missing: to"})
            if not ts or not sig:
                return self._respond(401, {"error": "missing auth: ts and sig required"})
            if not verify_inbox_auth(to, ts, params.get("after", "0"), sig):
                return self._respond(401, {"error": "auth failed"})

            db = sqlite3.connect(DB_PATH)
            db.row_factory = sqlite3.Row
            rows = db.execute(
                "SELECT id, date, sender, recipient, body, sig FROM mail WHERE recipient = ? AND id > ? ORDER BY id",
                (to, after),
            ).fetchall()
            db.close()
            mail = [{"id": r["id"], "date": r["date"], "from": r["sender"], "to": r["recipient"], "body": r["body"].hex(), "sig": r["sig"].hex()} for r in rows]
            self._respond(200, {"mail": mail})
        except Exception as e:
            log.error("GET error: %s", e)
            self._respond(500, {"error": str(e)})


class ThreadingMailServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 64


def main():
    with open(CONF_PATH) as f:
        cfg = json.load(f)

    host = cfg["bind_host"]
    port = cfg["port"]
    cert = cfg["cert"]
    key  = cfg["key"]
    if not isinstance(port, int) or port <= 0:
        raise ValueError("server.conf: 'port' must be a positive integer")
    if not os.path.isabs(cert):
        cert = os.path.join(DIR, cert)
    if not os.path.isabs(key):
        key = os.path.join(DIR, key)

    init_db()

    Handler.timeout = 10
    server = ThreadingMailServer((host, port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    log.info("mail server listening on https://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
