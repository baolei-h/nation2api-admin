# Notion2API Personal Admin

A personal, authenticated administration dashboard for a **previously patched** [`maverickxone/notion2api`](https://github.com/maverickxone/notion2api) VPS deployment. Does **not** replace existing `curl_cffi`, 38-model, model-ID or reasoning-effort patches.

## Capabilities

- Account pool: import the currently working `accounts.json` on first startup; add, rename, enable, disable, delete and test Notion sessions. Changes reload the in-memory pool without restarting. Existing in-flight requests retain their old client.
- API keys: independent, revocable keys displayed **once**, stored as SHA-256 digests. Daily/monthly requests and requests/minute limits; individual model allowlists.
- Model management: live enable/disable, custom client-ID to Notion-codename mapping, existing effort aliases retained. Original Notion AI Studio has a static model menu; new custom models appear in `/v1/models` and Cherry Studio after refreshing, not necessarily the existing Studio menu.
- Request dashboard: UTC-day request totals, HTTP status, model counts, per-key counts, recent audit operations. Does **not** store request/response text.
- Independent admin authentication: PBKDF2 password hash, 7-day HttpOnly SameSite=Strict cookie, CSRF checks for all admin changes, failed-login rate limit, encrypted Notion credentials in SQLite (Fernet). Existing legacy `accounts.json` is unchanged and **still contains plaintext** of imported credentials (required for the existing configuration module).
- One-step installer and rollback with original source and `.env` backups. All changes remain in the existing single-container Docker Compose service and SQLite volume.

**Limits:** Notion upstream does not provide an authoritative remaining balance in this project. The interface displays *local request quotas*, not official subscription credits or true token usage. HTTP 200 on a streaming request can be emitted before a later upstream failure. Statistics count accepted chat requests and gateway HTTP status, not guaranteed model generations.

## Public repository safety

**Do not commit `.env`, `accounts.json`, the `data/` directory, Notion session cookies, generated API keys, or real passwords.** All secrets must remain only on your VPS. The admin URL is HTTPS-only by default.

## Installation: Google Cloud VPS

Run **from the existing notion2api root**, while the original version is healthy:

```bash
cd ~/notion2api
curl -fL https://raw.githubusercontent.com/baolei-h/nation2api-admin/main/install.py -o install_admin.py
python3 install_admin.py
# Enter a NEW admin password of at least 14 characters twice. Password input is hidden.

docker compose config -q
docker compose up -d --build --force-recreate notion-ai
docker compose ps
python3 install_admin.py --check
```

`install.py` fetches source files from the same public repository under `{app/admin,frontend/admin}`. It backs up changed files before installing, and does **not** upload credentials to GitHub. `cryptography>=42,<48` is added to the existing `requirements.txt` if absent. The installer creates `ADMIN_FERNET_KEY` and `ADMIN_PASSWORD_HASH` in `.env` (chmod 600).

### Accessing the dashboard

- Recommended: reverse proxy HTTPS through a domain, e.g. `https://your-domain.example/admin/`. The proxy must pass the original HTTPS scheme to FastAPI from a *trusted* proxy address. Do not trust arbitrary public `X-Forwarded-Proto` headers.
- Existing VPS direct HTTP: **not recommended for a credential-management panel**. Only if you expressly accept plaintext password, cookies and session credentials during a temporary test, use `python3 install_admin.py --allow-http` during the **first** install, then `http://YOUR_VPS_IP:8000/admin/`. If already installed with HTTPS required, change `ADMIN_ALLOW_INSECURE_HTTP=0` to `1` in `.env` and recreate the container. This option is unsafe on public Wi-Fi and public Internet.
- Open `/admin/` and sign in with the new admin password. Existing chat remains at `/`, and `/v1` remains OpenAI-compatible. The original `.env` `API_KEY` remains valid by default and can be disabled through **安全设置**, after creating a new API Key.

### Reverse proxy security note

When using Caddy/Nginx in front of Docker, the FastAPI request scheme must be HTTPS. Uvicorn trusts forwarded headers from the configured `FORWARDED_ALLOW_IPS` only. Set this to the **exact reverse-proxy IP**, not `*`, and ensure the proxy overwrites `X-Forwarded-Proto`. Check your actual Docker networking before setting it. A separate management hostname is recommended.

### Quick smoke checks

```bash
curl -fsS http://127.0.0.1:8000/health
# Should include "accounts_total" for the number imported.
curl -i http://127.0.0.1:8000/admin/
# Should serve the login page (HTTP 200).
# Login itself requires HTTPS unless explicitly opted into HTTP.
```

Create a new API key in the admin panel, then configure Cherry Studio `http(s)://<server>/v1`, your new key and one of the listed model IDs. Send one brief prompt and confirm your request appears on the dashboard. Verify actual upstream model selection in Notion if necessary.

## Persistence and compatibility

- `data/notion_admin.sqlite3`: encrypted account vault, key hashes, quotas, sessions and usage logs, persisted through the existing `./data:/app/data` volume.
- `.env`: contains the **key required to decrypt** admin database account credentials; keep a private backup with the DB. Do not rotate `ADMIN_FERNET_KEY` without a migration. Keep `.env` out of public repositories.
- `accounts.json`: preserved for rollback and original `app.config`; its imported account token remains plaintext on disk. Only **new accounts added via the dashboard** are in the encrypted database. Restrict file permissions.
- `app/model_registry.py`, `app/notion_client.py`, prior `curl_cffi` changes and reasoning-effort aliases are not edited by the installer.
- API keys with a blank model list can call all globally enabled models. Disabling a base model also disables its `-effort-...` variants.
- Each API request reserve is transactionally counted for RPM and UTC daily/monthly quotas. `0` means unlimited. Legacy `.env` key bypasses **per-key quotas** until disabled; it still respects globally disabled models.
- If `model_registry.py` is later rebuilt by another update script, redeploy/restart and review custom-model name collisions. The admin database retains overrides, but original Notion Studio's hardcoded menu is not automatically rewritten.

## Safe rollback

```bash
cd ~/notion2api
python3 install_admin.py --rollback
docker compose up -d --build --force-recreate notion-ai
curl -fsS http://127.0.0.1:8000/health
```

The installer saves original `app/server.py`, `app/api/models.py`, `requirements.txt`, `.env`, and any previously installed admin files under `backups/admin_<timestamp>/`. Rollback restores prior code but **retains `.env` admin encryption variables and `data/notion_admin.sqlite3`**, making future reinstallation possible. The original `accounts.json` remains intact. Accounts **added only in the admin UI** will not be available to the old runtime after rollback; they can be recovered by reinstalling with the same encryption key.

If the installer was not finished, there should be no need to rollback because it validates downloads and patch anchors before changes. Keep a VPS snapshot for additional assurance.

## Test suite

Run locally with `fastapi`, `cryptography`, `httpx`, `pytest` available:

```bash
python -m pytest -q tests/test_admin.py
```

Tests include session+CSRF, account protections, model controls, local quotas, API-key model restrictions, legacy-key disable, HTTPS-only login and patcher idempotency. **Tests use synthetic stub account credentials, not real Notion accounts; the final live check must be performed on your VPS.**

## Scope

This is a **single-administrator, single-VPS** control panel, not a paid multi-tenant billing system. It does not access official Notion credit balances or add payment, sub-users, subscription resale, or provider price estimation.