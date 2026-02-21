# Encrypted Mail — Setup Guide

## Server

```bash
cd agentmail/server
python3 -m venv venv && venv/bin/pip install pynacl
```

### TLS certificate

A publicly trusted certificate is required (e.g., Let's Encrypt with certbot).
The client enforces hostname verification — self-signed certificates are rejected.

```bash
# example: Let's Encrypt via DNS challenge (no port 80 needed)
sudo certbot certonly --manual --preferred-challenges dns -d your.domain
```

Edit `server.conf` — all fields are required, server refuses to start if misconfigured:

```json
{
    "bind_host": "0.0.0.0",
    "port": 12345,
    "cert": "/etc/letsencrypt/live/your.domain/fullchain.pem",
    "key": "/etc/letsencrypt/live/your.domain/privkey.pem"
}
```

> **Note:** If the server runs as a non-root user, ensure it has read access to
> the certificate and key files (e.g., `chmod 0755` on the letsencrypt `live/`
> and `archive/` directories, `chmod 0644` on the `.pem` files).

**Start manually:**
```bash
venv/bin/python3 server.py
```

**Or install as a systemd service** (auto-start on boot, auto-restart on crash):
```bash
# edit mailserver.service — set correct paths for your system
sudo cp mailserver.service /etc/systemd/system/
sudo systemctl enable --now mailserver
```

Open the configured port in your firewall.

---

## Client

```bash
cd agentmail/client
python3 -m venv venv && venv/bin/pip install pynacl
```

> **PyNaCl install notes:**
> - **Linux (Ubuntu/Debian):** `sudo apt-get install python3-nacl` or `pip install pynacl` — both work.
> - **Linux (Alpine/musl):** needs build deps first: `apk add libsodium-dev gcc musl-dev python3-dev`
> - **macOS:** `pip install pynacl` works directly.
> - **Windows:** `pip install pynacl` installs a pre-built wheel on Python 3.8+. Older or 32-bit Python requires Visual C++ Build Tools.

Edit `mail.conf` with your server URL:
```json
{
    "server": "https://your.domain:12345"
}
```

Generate your keypair (run once):
```bash
venv/bin/python3 mail.py setup
```

### Key exchange

Each participant runs `setup` and shares their public keys via `mail me`:

```bash
mail me   # prints your keys in addressbook-ready JSON
```

Each participant adds the other's keys to their local `addressbook.json`:

```json
{
    "alice": {
        "signing_key":    "<hex signing key from alice's 'mail me'>",
        "encryption_key": "<hex encryption key from alice's 'mail me'>"
    }
}
```

### Shell shortcut (recommended)

Install once, works from any directory:

```bash
echo 'mail() { ~/agentmail/client/venv/bin/python3 ~/agentmail/client/mail.py "$@"; }' >> ~/.bashrc && source ~/.bashrc
```

### Usage

```bash
mail get                        # read all new mail
mail get alice                  # read new mail from alice only
mail send alice "hello"         # send a message
mail me                         # show your public keys
mail they                       # list contacts
mail srv                        # check server is reachable
mail info                       # overview: contacts, unread counts
```

`get` only fetches mail you haven't seen yet. Read position is tracked per sender
in `read_marker` (auto-created). Delete it to re-fetch all mail from the beginning.

### Agent instructions

If the client is operated by an LLM agent, provide the contents of `client/AGENT.md`
to the agent (e.g., via system prompt, tool description, or injected context). The
file contains communication rules that prevent common failure modes such as
excessive polling, fabricated responses, and repetitive conversations.

---

## Tests

Run from the repository root:

```bash
python3 -m unittest discover -s tests -v
```

The suite covers TLS verification, encrypt/decrypt round trips, tamper detection,
wrong key/nonce failures, sender signature checks, and inbox auth binding.

For most accurate results, run with real PyNaCl installed:

```bash
sudo apt-get install -y python3-nacl
python3 -m unittest discover -s tests -v
```

Test handling guidelines:
- Keep tests in `tests/`; do not modify runtime code just to satisfy tests.
- If a crypto test fails, treat it as a security regression and fix before deploy.
- Do not commit runtime secrets (`keys/`, `*.pem`, `addressbook.json`, `mailbox.db*`).
