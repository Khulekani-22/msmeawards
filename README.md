# Presidential MSME Awards — website

Static marketing site (24 pages) served by Vercel's CDN, plus a secure
**Node.js serverless contact API** and a **React + Axios** contact form.

## Architecture

| Layer | Tech | Notes |
|-------|------|-------|
| Marketing pages | Static HTML/CSS/JS | Served directly by Vercel (fast, SEO-friendly, reliable) |
| Contact form UI | React + Axios (Vite) | Built to `assets/contact-widget/contact-widget.js`, mounted on `contact.html` |
| Contact API | Node.js serverless (`/api`) | `api/contact.js`, `api/csrf.js`, shared `api/_lib/security.js` |
| Email delivery | [Resend](https://resend.com) via Axios | Recipient is fixed server-side |
| Rate limiting | Vercel KV / Upstash Redis (optional) | Durable across serverless invocations; fails open |

### Why hybrid (not a full SPA)?
For a mostly-static marketing site, keeping the pages as static HTML is the most
reliable and SEO-friendly option. Only the interactive contact form needs
React + a backend, so that is the only part that was refactored.

## Security (all stateless — safe on serverless)

- **Same-origin enforcement** — Origin/Referer must match `ALLOWED_ORIGINS`.
- **CSRF** — signed, time-limited HMAC token from `/api/csrf` (no sessions).
- **Honeypot** — hidden `website` field; silently drops bots.
- **Rate limiting** — per-IP fixed window via KV/Upstash (5/hour by default).
- **Cloudflare Turnstile** — optional; enforced only when keys are set.
- **Header-injection-safe `reply_to`** — CR/LF and control chars stripped.
- **Security headers** — CSP, HSTS, `X-Frame-Options`, nosniff via `vercel.json`.
- **Secrets** — live only in Vercel Environment Variables, never in the repo.

## Local development

```bash
npm install
cp .env.example .env      # fill in RESEND_API_KEY, RESEND_FROM_EMAIL, CSRF_SECRET
npm install -g vercel     # first time only
vercel dev                # runs the static site + /api functions locally
```

Edit the form UI in `src/contact/`, then rebuild the widget:

```bash
npm run build             # outputs assets/contact-widget/contact-widget.js
```

## Deploying to Vercel

1. Push to GitHub and import the repo in Vercel.
2. **Project → Settings → Environment Variables** — add:
   - `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `CONTACT_TO_EMAIL`
   - `ALLOWED_ORIGINS` (your production domains)
   - `CSRF_SECRET` (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`)
   - *(optional)* `TURNSTILE_SECRET_KEY` + set the site key in `contact.html`
     (`window.CONTACT_TURNSTILE_SITEKEY`) or `VITE_TURNSTILE_SITEKEY` at build time
   - *(optional)* Vercel **KV** integration for rate limiting (auto-injects
     `KV_REST_API_URL` / `KV_REST_API_TOKEN`)
3. Verify the sending domain in Resend and add **SPF, DKIM, and DMARC** DNS records.
4. Deploy.

## Repository layout

```
api/
  contact.js          # POST — validate + send via Resend
  csrf.js             # GET  — issue signed CSRF token
  _lib/security.js    # shared stateless security helpers
src/contact/          # React contact form source (built by Vite)
assets/contact-widget/contact-widget.js   # built widget (committed)
*.html                # static marketing pages
vercel.json           # headers, clean URLs, function config
```
