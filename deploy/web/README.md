# Experimental, community-supported web edition

This experimental, community-supported Docker Compose deployment serves Sprigo in a browser. It is separate from the Tauri desktop app and its [phone companion](../../docs/MOBILE.md). The browser provides the screen, microphone and speaker; the server runs the UI, a restricted Ollama proxy and CPU-based faster-whisper (`base.en`). Piper runs in the browser and downloads its voice on first use.

## Start

Requires Docker Compose, OpenSSL and an Ollama server reachable from Docker. Pull the configured model in Ollama first (`ollama pull qwen3:8b` by default). Set `SPRIGO_MODEL` in `.env` if you prefer a different installed model. Ollama must be reachable from inside the container; on Linux, the default host gateway URL may require you to configure Ollama to listen beyond `127.0.0.1`, or set `SPRIGO_OLLAMA_URL` to another reachable endpoint. Whisper downloads its model on the first transcription.

```sh
cd deploy/web
cp .env.example .env
# Set SPRIGO_ACCESS_PASSWORD in .env to a random secret (for example, use `openssl rand -base64 32`).
# Edit .env: set SPRIGO_BIND_IP to this server's LAN or VPN address for other devices.
# Set SPRIGO_UID and SPRIGO_GID to the local account that runs Docker (id -u, id -g).
./web-cert.sh 192.168.1.50  # replace with the address or DNS name used in the browser
mkdir -p models server-data
chmod 700 server-data
# Make sure the configured UID/GID can write models and server-data.
docker compose up -d --build
```

Open `https://<address>:1431/` (or the configured HTTPS port). A phone's microphone requires a trusted HTTPS connection. The generated local CA certificate is `certs/ca.crt`; install it on each device through a trusted transfer and verify its fingerprint. The certificate is also available at `http://<address>:1432/ca.crt` on a trusted LAN, but an HTTP download alone cannot authenticate a CA certificate. To see the fingerprint on the server:

```sh
openssl x509 -in certs/ca.crt -noout -fingerprint -sha256
```

If you already have a trusted TLS certificate for the chosen address, place its certificate, key and issuer certificate at `certs/server.crt`, `certs/server.key` and `certs/ca.crt`. The certificate download port is optional. This account-enabled edition requires the site access password for the UI, Ollama proxy and transcription. Keep it private and restrict network access. Do not expose the deployment directly to the public internet.

## Data and devices

By default, each browser stores profiles and progress in IndexedDB. An optional shared account stores one copy per account in `server-data/accounts/` and can be used by multiple browsers on this server. Creating an account can copy one browser's local database; it does not merge databases from different devices. Switching back to local mode ends the account session and keeps that browser's local data. The Tauri desktop app keeps its own database. Back up `server-data/` yourself; there is no cloud backup or self-service password recovery.

Only the configured Ollama model is proxied. Speech recognition in this experimental edition is currently **English only** with `base.en`. Other course languages need a multilingual Whisper model. The generated CA private key and server key stay in the ignored `certs/` directory; never commit them. The separate desktop app's Tailscale phone mode remains available.

## Shared account security

Enter the site access password with username `sprigo` when your browser asks. Then create an individual shared account with a password of at least eight characters. Registration and login are rate limited, registration and database imports have size limits, and the server limits SQL queries and request time. The account session uses a Secure, HttpOnly, SameSite cookie. The site password is kept in ignored `.env`; account data is kept in ignored `server-data/`.

The server is configured for one Ollama model and does not store a cloud AI API key. If a browser user separately chooses a cloud provider, the current client stores that key in that browser's localStorage; it is not synchronized with the account. Treat this mode as experimental and avoid storing cloud keys in a shared browser. A stale device write is rejected and its page reloads instead of silently overwriting newer progress. There is still no general merge of simultaneous edits; use one device at a time.
