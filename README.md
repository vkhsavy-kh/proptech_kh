# PropTech — Cloudflare Edition

Cambodia-focused real-estate agency portal + CRM designed for Cloudflare Workers.

## Architecture
- Cloudflare Workers + Hono API/web shell
- D1 relational database
- R2 property media storage
- KV sessions
- Queues for notifications/background work
- Telegram Login OIDC integration scaffold

Cloudflare currently recommends vinext for new Next.js applications on Workers. This package intentionally uses a Workers-native Hono application for the first deployable backend/web shell; the UI can later be moved to a Workers-ready Next.js/vinext app without changing the D1/R2/RBAC model.

## 1. Requirements
- Node.js 20+
- Cloudflare account
- Wrangler login: `npx wrangler login`

## 2. Install
```bash
npm install
```

## 3. Create Cloudflare resources
```bash
npx wrangler d1 create proptech-db
npx wrangler r2 bucket create proptech-media
npx wrangler kv namespace create PROPTECH_SESSIONS
npx wrangler queues create proptech-notifications
```
Copy the IDs into `wrangler.jsonc`.

## 4. Database
Local:
```bash
npm run db:local
```
Remote:
```bash
npm run db:remote
```

## 5. Secrets
Telegram requires a BotFather-created Login/OIDC client. Set secrets:
```bash
npx wrangler secret put TELEGRAM_CLIENT_ID
npx wrangler secret put TELEGRAM_CLIENT_SECRET
```
Also configure the exact production redirect URI in BotFather.

## 6. Deploy
```bash
npm run deploy
```

## 7. Custom domain
Attach your domain to the Worker in Cloudflare, then update `APP_URL` and `TELEGRAM_REDIRECT_URI` in `wrangler.jsonc`.

## Security before production
- ~~Replace the SHA-256 password demo with PBKDF2/Argon2-compatible password hashing.~~ Done: PBKDF2-HMAC-SHA256, 100k iterations, per-password random salt, constant-time comparison, with legacy hashes upgraded on next successful login.
- Complete Telegram authorization-code exchange and JWKS ID-token signature/claims verification.
- Add CSRF protections where cookie-authenticated state-changing browser requests are used.
- Implement R2 presigned uploads and object access policy.
- Add rate limiting, email/phone verification, password reset, 2FA for admins, and audit UI.
- Add full property edit/delete/approve/publish APIs with permission checks.
- Add photo processing, maps, customer/lead workflows, and Telegram notifications.
