<?php
/**
 * Contact form endpoint — sends messages via the Resend API.
 * ---------------------------------------------------------------------------
 * Receives a JSON (or form-encoded) POST from assets/js/contact.js, validates
 * it, and relays the message as an email using Resend (https://resend.com).
 *
 * Abuse protections (see api/security.php):
 *   - Security response headers (nosniff, no-frame, HSTS on HTTPS)
 *   - Same-origin enforcement via Origin/Referer allowlist
 *   - CSRF synchronizer token tied to the session
 *   - Honeypot field for naive bots
 *   - Per-IP sliding-window rate limiting
 *   - Optional Cloudflare Turnstile verification
 *   - Header-injection-safe reply_to
 *   - Append-only audit logging
 *
 * Secrets live in ../.env (never commit real keys):
 *   Resend_API_Key=re_xxxxxxxx        (Resend API key)
 *   RESEND_FROM_EMAIL=info@your-verified-domain.org
 *   CONTACT_TO_EMAIL=where-to-deliver@your-domain.org   (optional)
 *   ALLOWED_ORIGINS=https://msmeawards.org,https://www.msmeawards.org
 *   TURNSTILE_SECRET_KEY=...                              (optional)
 * ---------------------------------------------------------------------------
 */

declare(strict_types=1);

require __DIR__ . '/security.php';

/* Baseline security headers + JSON, no-store. */
send_security_headers();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

/* Load .env early so origin allowlist + keys are available. */
load_env();

/* ---------------------------------------------------------------------------
 * Only allow POST
 * ------------------------------------------------------------------------- */
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'OPTIONS') {
    // Same-origin requests won't preflight, but respond politely just in case.
    header('Allow: POST, OPTIONS');
    respond(204, []);
}
if ($method !== 'POST') {
    header('Allow: POST, OPTIONS');
    respond(405, ['ok' => false, 'error' => 'Method not allowed.']);
}

/* ---------------------------------------------------------------------------
 * Same-origin enforcement (CSRF defense layer 1)
 * ------------------------------------------------------------------------- */
enforce_same_origin();

/* ---------------------------------------------------------------------------
 * Resend credentials (from .env)
 * ------------------------------------------------------------------------- */
$apiKey    = env_value('Resend_API_Key', env_value('RESEND_API_KEY'));
$fromEmail = env_value('RESEND_FROM_EMAIL');
$toEmail   = env_value('CONTACT_TO_EMAIL', $fromEmail);

if (!$apiKey || !$fromEmail) {
    respond(500, [
        'ok'    => false,
        'error' => 'Email service is not configured. Please try again later.',
    ]);
}

/* ---------------------------------------------------------------------------
 * Parse the incoming payload (JSON preferred, form-encoded fallback)
 * ------------------------------------------------------------------------- */
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
$data        = [];

if (stripos($contentType, 'application/json') !== false) {
    $raw     = file_get_contents('php://input') ?: '';
    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
        $data = $decoded;
    }
} else {
    $data = $_POST;
}

/** Read + trim a string field from the payload. */
function field(array $data, string $key): string
{
    $value = $data[$key] ?? '';
    return is_string($value) ? trim($value) : '';
}

$name      = field($data, 'name');
$email     = field($data, 'email');
$subject   = field($data, 'subject');
$message   = field($data, 'message');
$honey     = field($data, 'website');        // honeypot — humans never fill this in
$csrf      = field($data, 'csrf_token');     // CSRF synchronizer token
$turnstile = field($data, 'turnstile_token'); // Cloudflare Turnstile response

/* ---------------------------------------------------------------------------
 * Spam honeypot: if filled, pretend success without sending anything.
 * ------------------------------------------------------------------------- */
if ($honey !== '') {
    respond(200, ['ok' => true]);
}

/* ---------------------------------------------------------------------------
 * CSRF token (defense layer 2, tied to the session)
 * ------------------------------------------------------------------------- */
if (!csrf_validate($csrf)) {
    respond(419, [
        'ok'    => false,
        'error' => 'Your session has expired. Please refresh the page and try again.',
    ]);
}

/* ---------------------------------------------------------------------------
 * Per-IP rate limiting
 * ------------------------------------------------------------------------- */
$ip = client_ip();
[$allowed, $retryAfter] = rate_limit($ip, CONTACT_RATE_LIMIT_MAX, CONTACT_RATE_LIMIT_WINDOW);
if (!$allowed) {
    if ($retryAfter > 0) {
        header('Retry-After: ' . $retryAfter);
    }
    contact_log(['ip' => $ip, 'status' => 'rate_limited', 'email' => $email]);
    respond(429, [
        'ok'    => false,
        'error' => 'Too many messages from your connection. Please try again in a little while.',
    ]);
}

/* ---------------------------------------------------------------------------
 * Validation
 * ------------------------------------------------------------------------- */
$errors = [];

if ($name === '' || mb_strlen($name) > 100) {
    $errors['name'] = 'Please enter your name (up to 100 characters).';
}
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 150) {
    $errors['email'] = 'Please enter a valid email address.';
}
if ($subject !== '' && mb_strlen($subject) > 150) {
    $errors['subject'] = 'Subject is too long (up to 150 characters).';
}
if ($message === '' || mb_strlen($message) > 5000) {
    $errors['message'] = 'Please enter a message (up to 5000 characters).';
}

if ($errors) {
    respond(422, [
        'ok'     => false,
        'error'  => 'Please review the highlighted fields and try again.',
        'fields' => $errors,
    ]);
}

/* ---------------------------------------------------------------------------
 * Bot verification (Cloudflare Turnstile) — enforced only when configured
 * ------------------------------------------------------------------------- */
if (!verify_turnstile($turnstile, $ip)) {
    contact_log(['ip' => $ip, 'status' => 'turnstile_failed', 'email' => $email]);
    respond(403, [
        'ok'    => false,
        'error' => 'Verification failed. Please complete the challenge and try again.',
    ]);
}

/* ---------------------------------------------------------------------------
 * Build the email
 * ------------------------------------------------------------------------- */
$safeName    = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$safeEmail   = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
$safeSubject = htmlspecialchars($subject !== '' ? $subject : 'No subject', ENT_QUOTES, 'UTF-8');
$safeMessage = nl2br(htmlspecialchars($message, ENT_QUOTES, 'UTF-8'));

$emailSubject = 'New contact message: ' . sanitize_header_line($subject !== '' ? $subject : 'Website enquiry');

$html = <<<HTML
<div style="font-family:Arial,Helvetica,sans-serif;max-width:600px;margin:0 auto;color:#211d1d;">
  <div style="background:linear-gradient(171deg,#232321 0%,#0e0202 100%);color:#f4f2ed;padding:20px 24px;border-radius:12px 12px 0 0;">
    <h2 style="margin:0;font-size:18px;">Presidential MSME Awards &mdash; Contact Form</h2>
  </div>
  <div style="border:1px solid #ececec;border-top:0;border-radius:0 0 12px 12px;padding:24px;">
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      <tr><td style="padding:6px 0;color:#8a827a;width:90px;">Name</td><td style="padding:6px 0;font-weight:600;">$safeName</td></tr>
      <tr><td style="padding:6px 0;color:#8a827a;">Email</td><td style="padding:6px 0;font-weight:600;"><a href="mailto:$safeEmail" style="color:#c08a3e;">$safeEmail</a></td></tr>
      <tr><td style="padding:6px 0;color:#8a827a;">Subject</td><td style="padding:6px 0;font-weight:600;">$safeSubject</td></tr>
    </table>
    <hr style="border:0;border-top:1px solid #ececec;margin:16px 0;">
    <p style="margin:0 0 8px;color:#8a827a;font-size:13px;">Message</p>
    <div style="font-size:14px;line-height:1.7;">$safeMessage</div>
  </div>
  <p style="text-align:center;color:#9a938c;font-size:12px;margin:16px 0 0;">
    Sent from the msmeawards.org contact form
  </p>
</div>
HTML;

$text = "New contact message\n\n"
      . "Name: {$name}\n"
      . "Email: {$email}\n"
      . "Subject: " . ($subject !== '' ? $subject : 'No subject') . "\n\n"
      . "Message:\n{$message}\n";

$payload = [
    'from'     => 'Presidential MSME Awards <' . $fromEmail . '>',
    'to'       => [$toEmail],
    'subject'  => $emailSubject,
    'html'     => $html,
    'text'     => $text,
    'reply_to' => safe_reply_to($name, $email),
];

/* ---------------------------------------------------------------------------
 * Send via the Resend API
 * ------------------------------------------------------------------------- */
if (!function_exists('curl_init')) {
    respond(500, ['ok' => false, 'error' => 'Server is missing the cURL extension.']);
}

$ch = curl_init('https://api.resend.com/emails');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_HTTPHEADER     => [
        'Authorization: Bearer ' . $apiKey,
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
    CURLOPT_TIMEOUT        => 20,
    CURLOPT_CONNECTTIMEOUT => 10,
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlErr  = curl_error($ch);
curl_close($ch);

if ($response === false) {
    error_log('[contact] Resend request failed: ' . $curlErr);
    contact_log(['ip' => $ip, 'status' => 'send_unreachable', 'email' => $email]);
    respond(502, [
        'ok'    => false,
        'error' => 'We could not reach the email service. Please try again later.',
    ]);
}

$result = json_decode($response, true);

if ($httpCode >= 200 && $httpCode < 300 && isset($result['id'])) {
    contact_log([
        'ip'      => $ip,
        'status'  => 'sent',
        'email'   => $email,
        'subject' => $subject,
        'id'      => $result['id'],
    ]);
    respond(200, ['ok' => true, 'id' => $result['id']]);
}

// Log the provider error server-side; keep the client message generic.
error_log('[contact] Resend error ' . $httpCode . ': ' . $response);
contact_log(['ip' => $ip, 'status' => 'send_error', 'email' => $email, 'http' => $httpCode]);
respond(502, [
    'ok'    => false,
    'error' => 'Sorry, your message could not be sent right now. Please try again later.',
]);
