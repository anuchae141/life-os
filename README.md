
# Life OS — COMPLETE v1.0.0

Secure + Biometric PWA for daily planning, weekly Big 3, and habit tracking.
- AES-256-GCM with PBKDF2 (200k) — client-side encryption using your passcode
- Optional WebAuthn (Face/Touch ID) as client gate (requires HTTPS or localhost)
- Offline-first with Service Worker
- Strict CSP via meta (no inline scripts/styles)

## Files
- index.html — main app (no inline JS/CSS; strict CSP)
- styles.css — styles
- app.js — logic (encryption, WebAuthn, UI)
- service-worker.js — cache + offline fallback
- offline.html — fallback page
- manifest.webmanifest — PWA manifest
- icon-192.png, icon-512.png, apple-touch-icon-180.png — icons

## Deploy
1. Serve this folder over **HTTPS** (or use `localhost` for testing).
2. Open `index.html` in your browser.
3. iOS (Safari): Share → **Add to Home Screen**. Android (Chrome): **Add to Home screen / Install app**.

## Security Notes
- All data is encrypted at rest in `localStorage`. Forgetting your passcode means data cannot be recovered.
- WebAuthn here acts as a client gate only. For server-verified WebAuthn, add a backend that issues and verifies challenges.
- Suggested HTTP headers:
  - Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'
  - Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  - X-Content-Type-Options: nosniff
  - Referrer-Policy: no-referrer
  - Permissions-Policy: geolocation=(), camera=(), microphone=()

## Version
- Version: 1.0.0
- Build: 2025-08-25 08:42
