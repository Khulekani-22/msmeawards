// api/_lib/security.js
// ---------------------------------------------------------------------------
// Shared, STATELESS security helpers for the Vercel serverless contact API.
// Everything here is designed to work on ephemeral serverless instances:
//   - CSRF uses a signed HMAC token (no server-side session storage)
//   - Rate limiting uses Upstash / Vercel KV over REST (durable) when
//     configured, and degrades gracefully to "allow" when it is not
//   - No local filesystem writes (serverless filesystems are ephemeral)
// ---------------------------------------------------------------------------

import crypto from 'node:crypto';
import axios from 'axios';

/* ---------------------------------------------------------------------------
 * Environment helpers
 * ------------------------------------------------------------------------- */
export function env(name, fallback = '') {
  const v = process.env[name];
  return v === undefined || v === null ? fallback : String(v).trim();
}

/** Resend API key — supports either casing used historically. */
export function resendApiKey() {
  return env('RESEND_API_KEY') || env('Resend_API_Key');
}

/* ---------------------------------------------------------------------------
 * JSON response + security headers
 * ------------------------------------------------------------------------- */
export function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
}

export function sendJson(res, status, body) {
  res.status(status).setHeader('Content-Type', 'application/json; charset=utf-8');
  res.send(JSON.stringify(body));
}

/* ---------------------------------------------------------------------------
 * Origin allowlist (defense layer 1)
 * ------------------------------------------------------------------------- */
export function allowedOrigins() {
  const defaults = [
    'https://msmeawards.org',
    'https://www.msmeawards.org',
  ];
  // Vercel injects the deployment URL; allow it so previews work.
  const vercelUrl = env('VERCEL_URL');
  if (vercelUrl) defaults.push(`https://${vercelUrl}`);

  const extra = env('ALLOWED_ORIGINS')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  return Array.from(new Set([...defaults, ...extra]));
}

function normalizeOrigin(url) {
  try {
    const u = new URL(url);
    const port = u.port ? `:${u.port}` : '';
    return `${u.protocol}//${u.hostname}${port}`.toLowerCase();
  } catch {
    return null;
  }
}

export function originAllowed(url) {
  if (!url) return false;
  let host;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  // Dev convenience: loopback on any port.
  if (['localhost', '127.0.0.1', '::1'].includes(host)) return true;

  const norm = normalizeOrigin(url);
  return allowedOrigins().some((o) => normalizeOrigin(o) === norm);
}

/**
 * Reject cross-origin POSTs. Uses Origin, falling back to Referer.
 * @returns {boolean} true if allowed
 */
export function enforceSameOrigin(req) {
  const origin = req.headers.origin;
  if (origin) return originAllowed(origin);
  const referer = req.headers.referer;
  if (referer) return originAllowed(referer);
  // No Origin/Referer: let the CSRF token be the deciding factor.
  return true;
}

/* ---------------------------------------------------------------------------
 * Stateless CSRF (defense layer 2) — signed, time-limited HMAC token
 * ------------------------------------------------------------------------- */
function csrfSecret() {
  // A dedicated secret is strongly recommended; fall back to the Resend key so
  // the mechanism still functions if CSRF_SECRET is not set.
  return env('CSRF_SECRET') || resendApiKey() || 'insecure-dev-secret';
}

const CSRF_TTL_SECONDS = 60 * 30; // 30 minutes

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/** Issue a signed token: base64url(payload).base64url(hmac) */
export function issueCsrfToken() {
  const payload = JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + CSRF_TTL_SECONDS,
    nonce: crypto.randomBytes(8).toString('hex'),
  });
  const sig = crypto.createHmac('sha256', csrfSecret()).update(payload).digest();
  return `${b64url(payload)}.${b64url(sig)}`;
}

/** Constant-time verification of a signed CSRF token. */
export function verifyCsrfToken(token) {
  if (typeof token !== 'string' || !token.includes('.')) return false;
  const [payloadB64, sigB64] = token.split('.', 2);
  if (!payloadB64 || !sigB64) return false;

  let payloadStr;
  try {
    payloadStr = Buffer.from(payloadB64, 'base64url').toString('utf8');
  } catch {
    return false;
  }

  const expected = crypto
    .createHmac('sha256', csrfSecret())
    .update(payloadStr)
    .digest();
  let provided;
  try {
    provided = Buffer.from(sigB64, 'base64url');
  } catch {
    return false;
  }
  if (expected.length !== provided.length) return false;
  if (!crypto.timingSafeEqual(expected, provided)) return false;

  try {
    const { exp } = JSON.parse(payloadStr);
    return typeof exp === 'number' && exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

/* ---------------------------------------------------------------------------
 * Client IP + rate limiting (durable via Upstash/Vercel KV REST)
 * ------------------------------------------------------------------------- */
export function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) {
    return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '0.0.0.0';
}

function kvConfig() {
  const url = env('KV_REST_API_URL') || env('UPSTASH_REDIS_REST_URL');
  const token = env('KV_REST_API_TOKEN') || env('UPSTASH_REDIS_REST_TOKEN');
  return url && token ? { url, token } : null;
}

/**
 * Fixed-window per-key rate limit backed by KV. Uses INCR + EXPIRE.
 * Fails OPEN (allows) if KV is unreachable or unconfigured so a backend
 * hiccup never blocks legitimate users.
 *
 * @returns {Promise<{allowed:boolean, remaining:number, retryAfter:number, enforced:boolean}>}
 */
export async function rateLimit(key, max = 5, windowSeconds = 3600) {
  const cfg = kvConfig();
  if (!cfg) {
    return { allowed: true, remaining: max, retryAfter: 0, enforced: false };
  }

  const redisKey = `rl:${crypto.createHash('sha256').update(key).digest('hex')}`;
  const headers = { Authorization: `Bearer ${cfg.token}` };

  try {
    // Pipeline: INCR then (conditionally) EXPIRE.
    const incrRes = await axios.post(
      `${cfg.url}/incr/${encodeURIComponent(redisKey)}`,
      null,
      { headers, timeout: 2000 }
    );
    const count = Number(incrRes.data?.result ?? 0);

    if (count === 1) {
      await axios.post(
        `${cfg.url}/expire/${encodeURIComponent(redisKey)}/${windowSeconds}`,
        null,
        { headers, timeout: 2000 }
      );
    }

    const allowed = count <= max;
    let retryAfter = 0;
    if (!allowed) {
      try {
        const ttlRes = await axios.get(
          `${cfg.url}/ttl/${encodeURIComponent(redisKey)}`,
          { headers, timeout: 2000 }
        );
        retryAfter = Math.max(1, Number(ttlRes.data?.result ?? windowSeconds));
      } catch {
        retryAfter = windowSeconds;
      }
    }
    return { allowed, remaining: Math.max(0, max - count), retryAfter, enforced: true };
  } catch {
    // Fail open.
    return { allowed: true, remaining: max, retryAfter: 0, enforced: false };
  }
}

/* ---------------------------------------------------------------------------
 * Cloudflare Turnstile
 * ------------------------------------------------------------------------- */
export async function verifyTurnstile(token, ip) {
  const secret = env('TURNSTILE_SECRET_KEY');
  if (!secret) return true; // disabled until configured
  if (!token) return false;

  try {
    const params = new URLSearchParams({ secret, response: token });
    if (ip) params.append('remoteip', ip);
    const { data } = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      params.toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 5000,
      }
    );
    return Boolean(data?.success);
  } catch {
    return false;
  }
}

/* ---------------------------------------------------------------------------
 * Input sanitisation
 * ------------------------------------------------------------------------- */
/** Strip CR/LF and control characters from a single-line value. */
export function sanitizeHeaderLine(value) {
  return String(value ?? '')
    .replace(/[\u0000-\u001F\u007F]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Build a header-injection-safe "Name <email>" reply_to. */
export function safeReplyTo(name, email) {
  const mail = String(email ?? '').trim();
  if (!isValidEmail(mail)) return '';
  const clean = String(name ?? '')
    .replace(/[\u0000-\u001F\u007F]+/g, ' ')
    .replace(/["<>,;:\r\n]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return clean ? `${clean} <${mail}>` : mail;
}

export function isValidEmail(email) {
  const s = String(email ?? '');
  if (s.length > 150) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

/** Escape a value for safe inclusion in an HTML email body. */
export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Read and JSON-parse the request body (Vercel may pass a string or object). */
export async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body.length) {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }
  // Fallback: read the raw stream.
  return await new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => {
      raw += c;
      if (raw.length > 1_000_000) req.destroy(); // 1MB guard
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}
