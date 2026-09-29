# E-Mola referral prototype

This workspace contains a local multi-agent referral demo built on Python's standard library and SQLite. The applicant page is served by the API so browser submissions are same-origin.

## Run locally

```powershell
python server.py
```

Open the applicant flow at `http://127.0.0.1:8000/`. The server prints a one-time local admin token at startup. Open `/admin`, enter that token, and create an agent. Give the agent their username, one-time temporary password, referral URL, and Telegram pairing URL through a private channel. The agent signs in at `/agent` and must set a new password before viewing leads.

Use the `EN`/`PT` button on any page to change the interface language. The choice is remembered in the browser across pages.

## Telegram bot setup

The bot listener responds to `/start`, `/help`, and `/chatid`. For the first run, set the token in a PowerShell terminal without committing it:

```powershell
$env:EMOLA_TELEGRAM_BOT_TOKEN = Read-Host "Telegram bot token"
python server.py
```

Open the bot in Telegram and send `/start`. It replies with the chat ID. For a group destination, add the bot to the private admin group and send `/start` in that group. Stop the server with `Ctrl+C`, then set both values and restart:

```powershell
$env:EMOLA_TELEGRAM_BOT_TOKEN = Read-Host "Telegram bot token"
$env:EMOLA_TELEGRAM_CHAT_ID = Read-Host "Telegram admin chat ID"
python server.py
```

The server prints whether polling and admin alerts are enabled. With both variables configured, each accepted application creates a queued Telegram alert containing the application ID, loan amount/term, referral agent ID, and whether agent contact was authorized. Failed sends are retried with backoff. Do not put the bot token in source files or send it in chat. This polling listener requires outbound HTTPS access but no public webhook URL.

Agent login also requires SMTP settings. For Gmail, use an App Password (with 2-Step Verification enabled), not your normal Gmail password. Set these in the same PowerShell session before starting the server:

```powershell
$env:EMOLA_SMTP_HOST = "smtp.gmail.com"
$env:EMOLA_SMTP_PORT = "587"
$env:EMOLA_SMTP_USERNAME = Read-Host "SMTP Gmail address"
$env:EMOLA_SMTP_FROM = $env:EMOLA_SMTP_USERNAME
$secureSmtpPassword = Read-Host "Gmail App Password" -AsSecureString
$env:EMOLA_SMTP_PASSWORD = [System.Net.NetworkCredential]::new("", $secureSmtpPassword).Password
```

The admin enters each agent's email when creating their account. After password entry, that agent receives a six-digit login code by email. The code expires after five minutes, is limited to five attempts, and new codes are throttled to one per minute.

The referral link contains a signed, expiring token. Applications are attributed to its agent even when the applicant declines agent contact, but the agent dashboard and individual Telegram notification only include applications with explicit contact consent. Repeated submission IDs are idempotent. Data is stored in `emola.sqlite3` next to the server.

When creating an agent, share the generated Telegram pairing link privately with them. They must open it in a private chat with `@shacklebaybot` within 15 minutes. The link can only be used once; create a new agent pairing link if it expires. The admin chat still receives a separate minimal alert when `EMOLA_TELEGRAM_CHAT_ID` is configured. Set `EMOLA_TELEGRAM_BOT_USERNAME` if the bot username changes.

Run the API tests with:

```powershell
python -m unittest -v
```

## Scope and deployment

This is a local prototype, not a production lending platform. It does not collect E-Mola PINs, SMS codes, or credentials, and it does not send webhooks. The dashboard is the implemented lead-delivery channel.

Agent passwords are PBKDF2-hashed; login sessions use HttpOnly, SameSite cookies. Set `EMOLA_COOKIE_SECURE=1` when serving over HTTPS. Before any public deployment, add production-grade admin and agent authentication with revocation, rate limiting and abuse controls, audit logging, encrypted storage and backups, a privacy/retention policy, and operational monitoring. Store signing/admin secrets outside the project directory using `EMOLA_SIGNING_KEY` and `EMOLA_ADMIN_TOKEN`; use a reverse proxy for TLS. The built-in HTTP server and plaintext SQLite database are for local development only.