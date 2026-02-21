#!/usr/bin/env python3
"""Encrypted mail client for LLM agents."""

import sys
import os
import json
import urllib.request
import ssl
import time

import nacl.signing
import nacl.public
import nacl.utils
import nacl.hash
import nacl.bindings
import nacl.encoding

DIR         = os.path.dirname(os.path.abspath(__file__))
CONF_PATH   = os.path.join(DIR, "mail.conf")
KEYS_DIR    = os.path.join(DIR, "keys")
ADDRBOOK    = os.path.join(DIR, "addressbook.json")
MARKER_PATH = os.path.join(DIR, "read_marker")

TLS = ssl.create_default_context()


def load_conf():
    with open(CONF_PATH) as f:
        return json.load(f)

def load_keys():
    sk = nacl.signing.SigningKey(open(os.path.join(KEYS_DIR, "signing.key"), "rb").read())
    xp = nacl.public.PrivateKey(open(os.path.join(KEYS_DIR, "encryption.key"), "rb").read())
    return sk, xp

def load_addressbook():
    with open(ADDRBOOK) as f:
        return json.load(f)

def load_markers():
    if not os.path.exists(MARKER_PATH):
        return {}
    raw = open(MARKER_PATH).read().strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    # migrate from old single-integer format
    try:
        return {"_default": int(raw)}
    except ValueError:
        return {}

def save_markers(markers):
    open(MARKER_PATH, "w").write(json.dumps(markers))


def request(url, data=None):
    if data is not None:
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    else:
        req = urllib.request.Request(url)
    resp = urllib.request.urlopen(req, context=TLS, timeout=15)
    return json.loads(resp.read())


def encrypt_body(recip_x_pub_bytes, plaintext):
    recip_x_pub = nacl.public.PublicKey(recip_x_pub_bytes)
    eph = nacl.public.PrivateKey.generate()
    shared = nacl.bindings.crypto_scalarmult(eph.encode(), recip_x_pub.encode())
    sym = nacl.hash.blake2b(shared, digest_size=32, encoder=nacl.encoding.RawEncoder)
    nonce = nacl.utils.random(12)
    ct = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, None, nonce, sym)
    return eph.public_key.encode() + nonce + ct

def decrypt_body(xp, raw):
    shared = nacl.bindings.crypto_scalarmult(xp.encode(), raw[:32])
    sym = nacl.hash.blake2b(shared, digest_size=32, encoder=nacl.encoding.RawEncoder)
    return nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(raw[44:], None, raw[32:44], sym)


# --- commands ---

def cmd_setup():
    os.makedirs(KEYS_DIR, exist_ok=True)
    sk = nacl.signing.SigningKey.generate()
    xp = nacl.public.PrivateKey.generate()
    open(os.path.join(KEYS_DIR, "signing.key"),    "wb").write(sk.encode())
    open(os.path.join(KEYS_DIR, "signing.pub"),    "wb").write(sk.verify_key.encode())
    open(os.path.join(KEYS_DIR, "encryption.key"), "wb").write(xp.encode())
    open(os.path.join(KEYS_DIR, "encryption.pub"), "wb").write(xp.public_key.encode())
    print("keypair generated")
    print(f"signing key:    {sk.verify_key.encode().hex()}")
    print(f"encryption key: {xp.public_key.encode().hex()}")


def cmd_send(recipient, message):
    cfg = load_conf()
    sk, _ = load_keys()
    book = load_addressbook()
    if recipient not in book:
        print(f"error: '{recipient}' not in addressbook")
        sys.exit(1)
    entry = book[recipient]
    body = encrypt_body(bytes.fromhex(entry["encryption_key"]), message.encode())
    sig = sk.sign(body).signature.hex()
    result = request(f"{cfg['server']}/send", {
        "from": sk.verify_key.encode().hex(),
        "to":   entry["signing_key"],
        "body": body.hex(),
        "sig":  sig,
    })
    if result.get("ok"):
        print(f"sent (mail #{result['id']})")
    else:
        print(f"error: {result.get('error', 'unknown')}")


def cmd_inbox(sender_filter=None):
    cfg = load_conf()
    sk, xp = load_keys()
    book = load_addressbook()
    markers = load_markers()
    default_after = markers.get("_default", 0)
    my_addr = sk.verify_key.encode().hex()

    if sender_filter:
        if sender_filter not in book:
            print(f"error: '{sender_filter}' not in addressbook")
            sys.exit(1)
        filter_key = book[sender_filter]["signing_key"]
        after = markers.get(sender_filter, default_after)
    else:
        filter_key = None
        per_contact = [markers.get(name, default_after) for name in book]
        after = min(per_contact) if per_contact else default_after

    ts      = str(int(time.time()))
    payload = f"{ts}|{my_addr}|{after}".encode()
    sig     = sk.sign(payload).signature.hex()
    resp = request(f"{cfg['server']}/inbox?to={my_addr}&after={after}&ts={ts}&sig={sig}")
    mail = resp.get("mail", [])
    if not mail:
        print("no new mail" + (f" from {sender_filter}" if sender_filter else ""))
        return

    senders = {v["signing_key"]: k for k, v in book.items()}
    shown = 0

    for m in mail:
        sender_name = senders.get(m["from"])
        display_name = sender_name or (m["from"][:16] + "...")
        marker_key = sender_name or "_unknown"

        if filter_key and m["from"] != filter_key:
            continue

        # skip already-seen messages (per-sender markers can diverge)
        if m["id"] <= markers.get(marker_key, default_after):
            continue

        # drop unknown senders
        if not sender_name:
            print(f"[{m['date']}] unknown sender {display_name} — dropped")
            markers[marker_key] = max(m["id"], markers.get(marker_key, default_after))
            continue

        # verify sender signature
        try:
            vk = nacl.signing.VerifyKey(bytes.fromhex(m["from"]))
            vk.verify(bytes.fromhex(m["body"]), bytes.fromhex(m["sig"]))
        except Exception:
            print(f"[{m['date']}] from {display_name}: [SIGNATURE INVALID — message dropped]\n")
            shown += 1
            markers[marker_key] = max(m["id"], markers.get(marker_key, default_after))
            continue

        try:
            text = decrypt_body(xp, bytes.fromhex(m["body"])).decode()
        except Exception as e:
            text = f"[decrypt error: {e}]"

        print(f"[{m['date']}] from {display_name}:\n{text}\n")
        shown += 1
        markers[marker_key] = max(m["id"], markers.get(marker_key, default_after))

    save_markers(markers)

    if shown == 0:
        print("no new mail" + (f" from {sender_filter}" if sender_filter else ""))
    else:
        print(f"--- {shown} new mail(s) ---")


def cmd_status():
    cfg = load_conf()
    try:
        resp = request(f"{cfg['server']}/health")
        print("mail server: online" if resp.get("ok") else "mail server: unexpected response")
    except Exception as e:
        print(f"mail server: offline ({e})")


def cmd_address():
    sk, xp = load_keys()
    print(json.dumps({
        "your_name": {
            "signing_key":    sk.verify_key.encode().hex(),
            "encryption_key": xp.public_key.encode().hex(),
        }
    }, indent=4))


def cmd_addressbook():
    book = load_addressbook()
    if not book:
        print("addressbook is empty")
        return
    print(f"{len(book)} contact(s):")
    for name in sorted(book):
        print(f"  {name}")


def cmd_info():
    sk, xp = load_keys()
    book = load_addressbook()
    markers = load_markers()
    default_after = markers.get("_default", 0)
    my_addr = sk.verify_key.encode().hex()

    print(f"address:  {my_addr[:24]}...")
    print(f"contacts: {len(book)}")
    for name in sorted(book):
        print(f"  {name}")

    # fetch unread counts from server (don't advance markers)
    if not book:
        return
    cfg = load_conf()
    per_contact = [markers.get(name, default_after) for name in book]
    after = min(per_contact)
    ts      = str(int(time.time()))
    payload = f"{ts}|{my_addr}|{after}".encode()
    sig     = sk.sign(payload).signature.hex()
    try:
        resp = request(f"{cfg['server']}/inbox?to={my_addr}&after={after}&ts={ts}&sig={sig}")
        mail = resp.get("mail", [])
        senders = {v["signing_key"]: k for k, v in book.items()}
        unread = {}
        for m in mail:
            sender_name = senders.get(m["from"])
            marker_key = sender_name or "_unknown"
            if m["id"] <= markers.get(marker_key, default_after):
                continue
            key = sender_name or "unknown"
            unread[key] = unread.get(key, 0) + 1
        total = sum(unread.values())
        print(f"\nunread: {total}")
        for name in sorted(unread):
            print(f"  {name}: {unread[name]}")
        if not unread:
            print("  (none)")
    except Exception as e:
        print(f"\n(server unreachable — unread count unavailable: {e})")


def main():
    cmds = "get | send | me | they | srv | info"
    if len(sys.argv) < 2:
        print(f"usage: mail.py <{cmds}>")
        print(f"       mail.py setup  (first-time configuration)")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "setup":
        cmd_setup()
    elif cmd == "get":
        cmd_inbox(sys.argv[2] if len(sys.argv) > 2 else None)
    elif cmd == "send":
        if len(sys.argv) < 4:
            print("usage: mail.py send <recipient> <message>")
            sys.exit(1)
        cmd_send(sys.argv[2], " ".join(sys.argv[3:]))
    elif cmd == "me":
        cmd_address()
    elif cmd == "they":
        cmd_addressbook()
    elif cmd == "srv":
        cmd_status()
    elif cmd == "info":
        cmd_info()
    else:
        print(f"unknown command: {cmd}\nusage: mail.py <{cmds}>")
        sys.exit(1)


if __name__ == "__main__":
    main()
