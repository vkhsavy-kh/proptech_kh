# PropTech — Cloudflare deployment

## 1. Install
Node.js 20+ is recommended.

```bash
npm install
npx wrangler login
```

## 2. Create Cloudflare resources
```bash
npx wrangler d1 create proptech-db
npx wrangler r2 bucket create proptech-media
npx wrangler kv namespace create PROPTECH_SESSIONS
npx wrangler queues create proptech-notifications
```
Put the returned D1/KV IDs in `wrangler.jsonc`.

## 3. Apply database
```bash
npm run db:remote
```

## 4. Telegram Login
Create/configure the bot Login/OIDC settings with @BotFather. Register:
- production origin: `https://YOUR-DOMAIN.com`
- redirect URI: `https://YOUR-DOMAIN.com/auth/telegram/callback`

Store credentials as Worker secrets:
```bash
npx wrangler secret put TELEGRAM_CLIENT_ID
npx wrangler secret put TELEGRAM_CLIENT_SECRET
```

The implementation uses Authorization Code + PKCE and verifies the Telegram ID token against Telegram's JWKS before creating a customer account.

## 5. Bootstrap the first Super Admin
Set a one-time secret:
```bash
npx wrangler secret put BOOTSTRAP_ADMIN_KEY
```
Then POST to `/api/setup/bootstrap-admin` with header `x-bootstrap-key` and JSON like:
```json
{"name":"PropTech Admin","email":"admin@yourdomain.com","phone":"+855...","password":"USE-A-LONG-RANDOM-PASSWORD"}
```
After creating the admin, remove/rotate `BOOTSTRAP_ADMIN_KEY`.

## 6. Deploy
```bash
npm run deploy
```

## 7. Custom domain
Attach your domain to the Worker in Cloudflare and change `APP_URL` and `TELEGRAM_REDIRECT_URI` in `wrangler.jsonc`.

## Production hardening
- Use a dedicated production password hashing scheme (PBKDF2/Argon2 service/library compatible with Workers) instead of the starter SHA-256 password helper.
- Add rate limiting to authentication and bootstrap routes.
- Add CSRF protection for cookie-authenticated browser mutations.
- Add password reset and optional phone verification.
- Add 2FA for admins.
- Add complete property edit/delete APIs and owner/customer CRUD screens.
- Add R2 image thumbnails/processing and moderation.
- Add Maps integration and marker editing.
- Add Telegram Bot notifications via the Queue.
- Add backup/export strategy for D1.
