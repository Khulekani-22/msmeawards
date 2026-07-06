// api/contact.js — Vercel serverless function that relays the contact form
// to email via the Resend API (using Axios). All security is stateless so it
// runs reliably on ephemeral serverless instances.
//
// Required env (set in the Vercel dashboard, never in the repo):
//   RESEND_API_KEY        Resend API key (sending-only)
//   RESEND_FROM_EMAIL     verified sender, e.g. info@msmeawards.org
// Recommended:
//   CONTACT_TO_EMAIL      recipient (defaults to RESEND_FROM_EMAIL)
//   ALLOWED_ORIGINS       comma-separated production origins
//   CSRF_SECRET           random 32+ byte secret for token signing
//   TURNSTILE_SECRET_KEY  Cloudflare Turnstile secret (optional)
//   KV_REST_API_URL/TOKEN Vercel KV / Upstash for durable rate limiting
import axios from 'axios';
import {
  applySecurityHeaders,
  sendJson,
  enforceSameOrigin,
  verifyCsrfToken,
  clientIp,
  rateLimit,
  verifyTurnstile,
  safeReplyTo,
  sanitizeHeaderLine,
  isValidEmail,
  escapeHtml,
  readJsonBody,
  resendApiKey,
  env,
} from './_lib/security.js';

const RATE_MAX = 5;
const RATE_WINDOW = 3600; // 1 hour

export default async function handler(req, res) {
  applySecurityHeaders(res);

  /* Method guard ---------------------------------------------------------- */
  if (req.method === 'OPTIONS') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(204).end();
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return sendJson(res, 405, { ok: false, error: 'Method not allowed.' });
  }

  /* Same-origin (CSRF layer 1) -------------------------------------------- */
  if (!enforceSameOrigin(req)) {
    return sendJson(res, 403, {
      ok: false,
      error: 'Cross-origin requests are not allowed.',
    });
  }

  /* Credentials ----------------------------------------------------------- */
  const apiKey = resendApiKey();
  const fromEmail = env('RESEND_FROM_EMAIL');
  const toEmail = env('CONTACT_TO_EMAIL') || fromEmail;
  if (!apiKey || !fromEmail) {
    return sendJson(res, 500, {
      ok: false,
      error: 'Email service is not configured. Please try again later.',
    });
  }

  /* Parse payload --------------------------------------------------------- */
  const data = await readJsonBody(req);
  const str = (k) => (typeof data[k] === 'string' ? data[k].trim() : '');
  const name = str('name');
  const email = str('email');
  const subject = str('subject');
  const message = str('message');
  const honey = str('website'); // honeypot
  const csrf = str('csrf_token');
  const turnstile = str('turnstile_token');

  /* Honeypot: silently succeed without sending ---------------------------- */
  if (honey !== '') {
    return sendJson(res, 200, { ok: true });
  }

  /* CSRF (layer 2) -------------------------------------------------------- */
  if (!verifyCsrfToken(csrf)) {
    return sendJson(res, 419, {
      ok: false,
      error: 'Your session has expired. Please refresh the page and try again.',
    });
  }

  /* Rate limiting --------------------------------------------------------- */
  const ip = clientIp(req);
  const rl = await rateLimit(`contact:${ip}`, RATE_MAX, RATE_WINDOW);
  if (!rl.allowed) {
    if (rl.retryAfter > 0) res.setHeader('Retry-After', String(rl.retryAfter));
    return sendJson(res, 429, {
      ok: false,
      error: 'Too many messages from your connection. Please try again later.',
    });
  }

  /* Validation ------------------------------------------------------------ */
  const errors = {};
  if (!name || name.length > 100) {
    errors.name = 'Please enter your name (up to 100 characters).';
  }
  if (!isValidEmail(email)) {
    errors.email = 'Please enter a valid email address.';
  }
  if (subject && subject.length > 150) {
    errors.subject = 'Subject is too long (up to 150 characters).';
  }
  if (!message || message.length > 5000) {
    errors.message = 'Please enter a message (up to 5000 characters).';
  }
  if (Object.keys(errors).length) {
    return sendJson(res, 422, {
      ok: false,
      error: 'Please review the highlighted fields and try again.',
      fields: errors,
    });
  }

  /* Bot verification (Turnstile; enforced only when configured) ----------- */
  const human = await verifyTurnstile(turnstile, ip);
  if (!human) {
    return sendJson(res, 403, {
      ok: false,
      error: 'Verification failed. Please complete the challenge and try again.',
    });
  }

  /* Build the email ------------------------------------------------------- */
  const safeName = escapeHtml(name);
  const safeEmail = escapeHtml(email);
  const safeSubject = escapeHtml(subject || 'No subject');
  const safeMessage = escapeHtml(message).replace(/\n/g, '<br>');
  const emailSubject =
    'New contact message: ' + sanitizeHeaderLine(subject || 'Website enquiry');

  const html = `
<div style="font-family:Arial,Helvetica,sans-serif;max-width:600px;margin:0 auto;color:#211d1d;">
  <div style="background:linear-gradient(171deg,#232321 0%,#0e0202 100%);color:#f4f2ed;padding:20px 24px;border-radius:12px 12px 0 0;">
    <h2 style="margin:0;font-size:18px;">Presidential MSME Awards &mdash; Contact Form</h2>
  </div>
  <div style="border:1px solid #ececec;border-top:0;border-radius:0 0 12px 12px;padding:24px;">
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      <tr><td style="padding:6px 0;color:#8a827a;width:90px;">Name</td><td style="padding:6px 0;font-weight:600;">${safeName}</td></tr>
      <tr><td style="padding:6px 0;color:#8a827a;">Email</td><td style="padding:6px 0;font-weight:600;"><a href="mailto:${safeEmail}" style="color:#c08a3e;">${safeEmail}</a></td></tr>
      <tr><td style="padding:6px 0;color:#8a827a;">Subject</td><td style="padding:6px 0;font-weight:600;">${safeSubject}</td></tr>
    </table>
    <hr style="border:0;border-top:1px solid #ececec;margin:16px 0;">
    <p style="margin:0 0 8px;color:#8a827a;font-size:13px;">Message</p>
    <div style="font-size:14px;line-height:1.7;">${safeMessage}</div>
  </div>
  <p style="text-align:center;color:#9a938c;font-size:12px;margin:16px 0 0;">Sent from the msmeawards.org contact form</p>
</div>`.trim();

  const text =
    `New contact message\n\n` +
    `Name: ${name}\n` +
    `Email: ${email}\n` +
    `Subject: ${subject || 'No subject'}\n\n` +
    `Message:\n${message}\n`;

  /* Send via Resend ------------------------------------------------------- */
  try {
    const { data: result } = await axios.post(
      'https://api.resend.com/emails',
      {
        from: `Presidential MSME Awards <${fromEmail}>`,
        to: [toEmail],
        subject: emailSubject,
        html,
        text,
        reply_to: safeReplyTo(name, email),
      },
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      }
    );

    if (result?.id) {
      return sendJson(res, 200, { ok: true, id: result.id });
    }
    return sendJson(res, 502, {
      ok: false,
      error: 'Sorry, your message could not be sent right now. Please try again later.',
    });
  } catch (err) {
    // Log server-side only; keep the client message generic.
    const status = err?.response?.status;
    console.error('[contact] Resend error', status, err?.response?.data || err?.message);
    return sendJson(res, 502, {
      ok: false,
      error: 'Sorry, your message could not be sent right now. Please try again later.',
    });
  }
}
