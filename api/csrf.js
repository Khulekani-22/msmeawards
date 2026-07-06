// api/csrf.js — issues a signed, stateless CSRF token for the contact form.
import {
  applySecurityHeaders,
  sendJson,
  issueCsrfToken,
} from './_lib/security.js';

export default function handler(req, res) {
  applySecurityHeaders(res);

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return sendJson(res, 405, { ok: false, error: 'Method not allowed.' });
  }

  return sendJson(res, 200, { ok: true, token: issueCsrfToken() });
}
