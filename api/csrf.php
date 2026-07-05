<?php
/**
 * CSRF token issuer.
 * ---------------------------------------------------------------------------
 * The contact page (static HTML) fetches this before submitting. It starts a
 * hardened session and returns a synchronizer token that api/contact.php then
 * verifies. Because no CORS headers are sent, cross-origin pages cannot read
 * the token.
 * ---------------------------------------------------------------------------
 */

declare(strict_types=1);

require __DIR__ . '/security.php';

send_security_headers();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    respond(405, ['ok' => false, 'error' => 'Method not allowed.']);
}

respond(200, ['ok' => true, 'token' => csrf_token()]);
