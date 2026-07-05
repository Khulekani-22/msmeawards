<?php
/**
 * Shared security + infrastructure helpers for the contact API.
 * ---------------------------------------------------------------------------
 * Included by api/contact.php and api/csrf.php. Provides:
 *   - send_security_headers()  security response headers
 *   - load_env() / env_value() .env loading
 *   - respond()                JSON responder
 *   - enforce_same_origin()    Origin/Referer allowlist (CSRF layer 1)
 *   - start_secure_session()   hardened session cookie
 *   - csrf_token()/csrf_validate()  synchronizer token (CSRF layer 2)
 *   - client_ip()              proxy-aware client IP
 *   - rate_limit()             per-IP sliding-window throttle
 *   - verify_turnstile()       Cloudflare Turnstile verification
 *   - safe_reply_to()          header-injection-safe reply_to
 *   - contact_log()            append-only audit log
 * ---------------------------------------------------------------------------
 */

declare(strict_types=1);

if (!defined('APP_ROOT')) {
    define('APP_ROOT', dirname(__DIR__));
}

/* Rate-limit configuration (per client IP). */
const CONTACT_RATE_LIMIT_MAX    = 5;    // max submissions...
const CONTACT_RATE_LIMIT_WINDOW = 3600; // ...per this many seconds (1 hour)

/* ---------------------------------------------------------------------------
 * JSON response
 * ------------------------------------------------------------------------- */
if (!function_exists('respond')) {
    /**
     * Emit a JSON response and stop.
     *
     * @param int   $status HTTP status code.
     * @param array $body   Response payload.
     */
    function respond(int $status, array $body): void
    {
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
        }
        http_response_code($status);
        echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }
}

/* ---------------------------------------------------------------------------
 * Security headers
 * ------------------------------------------------------------------------- */
/**
 * Send a baseline set of security headers. Page-level CSP is handled by
 * .htaccess (mod_headers); these guard the API even without Apache.
 */
function send_security_headers(): void
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header_remove('X-Powered-By');

    $https = (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
        || ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443);
    if ($https) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/* ---------------------------------------------------------------------------
 * Environment variables (.env)
 * ------------------------------------------------------------------------- */
/**
 * Read an environment variable from anywhere phpdotenv / the server populated
 * it, trimming stray whitespace (a value may have a leading space after "=").
 */
function env_value(string $key, ?string $default = null): ?string
{
    foreach ([$_ENV, $_SERVER] as $bag) {
        if (array_key_exists($key, $bag) && $bag[$key] !== '') {
            return trim((string) $bag[$key]);
        }
    }
    $fromGetenv = getenv($key);
    if ($fromGetenv !== false && $fromGetenv !== '') {
        return trim($fromGetenv);
    }
    return $default;
}

/**
 * Load environment variables from .env (prefers phpdotenv; falls back to a
 * tiny parser so the endpoint still works without Composer). Runs once.
 */
function load_env(?string $rootDir = null): void
{
    static $loaded = false;
    if ($loaded) {
        return;
    }
    $loaded  = true;
    $rootDir = $rootDir ?: APP_ROOT;

    $autoload = $rootDir . '/vendor/autoload.php';
    if (is_file($autoload)) {
        require_once $autoload;
    }

    if (class_exists(\Dotenv\Dotenv::class)) {
        try {
            \Dotenv\Dotenv::createImmutable($rootDir)->safeLoad();
            return;
        } catch (\Throwable $e) {
            // Fall through to the manual parser below.
        }
    }

    $envFile = $rootDir . '/.env';
    if (is_file($envFile)) {
        foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) {
                continue;
            }
            [$k, $v] = explode('=', $line, 2);
            $k = trim($k);
            $v = trim($v, " \t\"'");
            if ($k !== '' && getenv($k) === false) {
                putenv("$k=$v");
                $_ENV[$k] = $v;
            }
        }
    }
}

/* ---------------------------------------------------------------------------
 * Same-origin enforcement (CSRF defense layer 1)
 * ------------------------------------------------------------------------- */
/**
 * @return string[] Allowed web origins (scheme://host[:port]).
 */
function allowed_origins(): array
{
    $defaults = [
        'https://msmeawards.org',
        'https://www.msmeawards.org',
        'http://localhost',
        'http://127.0.0.1',
    ];
    $extra = env_value('ALLOWED_ORIGINS', '') ?? '';
    $list  = array_filter(array_map('trim', explode(',', $extra)));
    return array_values(array_unique(array_merge($defaults, $list)));
}

/** Normalise a URL/origin to "scheme://host[:port]" (default ports dropped). */
function normalize_origin(string $url): ?string
{
    $p = parse_url($url);
    if (!isset($p['scheme'], $p['host'])) {
        return null;
    }
    $scheme = strtolower($p['scheme']);
    $host   = strtolower($p['host']);
    $port   = isset($p['port']) ? (int) $p['port'] : ($scheme === 'https' ? 443 : 80);
    $suffix = in_array($port, [80, 443], true) ? '' : ':' . $port;
    return $scheme . '://' . $host . $suffix;
}

/** Is the given Origin/Referer URL allowed? */
function origin_allowed(string $url): bool
{
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    // Dev convenience: accept loopback on any port.
    if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
        return true;
    }
    $normalized = normalize_origin($url);
    if ($normalized === null) {
        return false;
    }
    foreach (allowed_origins() as $allowed) {
        if (normalize_origin($allowed) === $normalized) {
            return true;
        }
    }
    return false;
}

/**
 * Reject cross-origin requests. Uses Origin, falling back to Referer. When
 * neither header is present (rare), defers to the CSRF token check.
 */
function enforce_same_origin(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '') {
        if (!origin_allowed($origin)) {
            respond(403, ['ok' => false, 'error' => 'Cross-origin requests are not allowed.']);
        }
        return;
    }
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    if ($referer !== '') {
        if (!origin_allowed($referer)) {
            respond(403, ['ok' => false, 'error' => 'Cross-origin requests are not allowed.']);
        }
        return;
    }
    // No Origin/Referer: allow through; the CSRF token check will guard.
}

/* ---------------------------------------------------------------------------
 * Sessions + CSRF synchronizer token (CSRF defense layer 2)
 * ------------------------------------------------------------------------- */
function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $secure = (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'secure'   => $secure,
        'samesite' => 'Lax',
    ]);
    session_name('MSMESESS');
    @session_start();
}

/** Get (or lazily create) the CSRF token for this session. */
function csrf_token(): string
{
    start_secure_session();
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/** Constant-time validation of a submitted CSRF token. */
function csrf_validate(?string $token): bool
{
    start_secure_session();
    $stored = $_SESSION['csrf_token'] ?? '';
    return is_string($token) && $token !== ''
        && is_string($stored) && $stored !== ''
        && hash_equals($stored, $token);
}

/* ---------------------------------------------------------------------------
 * Client IP + rate limiting
 * ------------------------------------------------------------------------- */
/** Resolve the client IP (trusts Cloudflare only when TRUST_CLOUDFLARE=1). */
function client_ip(): string
{
    if (env_value('TRUST_CLOUDFLARE', '') === '1' && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = (string) $_SERVER['HTTP_CF_CONNECTING_IP'];
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

/**
 * Return an internal storage directory, creating it (locked-down) on demand.
 */
function storage_path(string $sub = ''): string
{
    $base = APP_ROOT . '/storage';
    if (!is_dir($base)) {
        @mkdir($base, 0775, true);
        @file_put_contents($base . '/.htaccess', "Require all denied\nDeny from all\n");
        @file_put_contents($base . '/index.html', '');
    }
    if ($sub === '') {
        return $base;
    }
    $dir = $base . '/' . trim($sub, '/');
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    return $dir;
}

/**
 * Sliding-window per-IP rate limit. Atomically checks and records a hit.
 *
 * @return array{0:bool,1:int} [allowed, retryAfterSeconds]
 */
function rate_limit(string $ip, int $max, int $window): array
{
    $file = storage_path('ratelimit') . '/' . hash('sha256', $ip) . '.json';
    $now  = time();

    $fp = @fopen($file, 'c+');
    if ($fp === false) {
        // Fail open so a broken storage layer can't lock out real users.
        return [true, 0];
    }

    flock($fp, LOCK_EX);
    $raw  = stream_get_contents($fp) ?: '[]';
    $hits = json_decode($raw, true);
    if (!is_array($hits)) {
        $hits = [];
    }
    // Keep only timestamps within the window.
    $hits = array_values(array_filter($hits, static function ($t) use ($now, $window) {
        return is_int($t) && $t > ($now - $window);
    }));

    $allowed = count($hits) < $max;
    if ($allowed) {
        $hits[] = $now;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($hits));
    }
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    $retryAfter = 0;
    if (!$allowed && $hits) {
        $retryAfter = max(1, (min($hits) + $window) - $now);
    }
    return [$allowed, $retryAfter];
}

/* ---------------------------------------------------------------------------
 * Cloudflare Turnstile
 * ------------------------------------------------------------------------- */
/**
 * Verify a Turnstile token. Returns true (skips) when no secret is configured,
 * so the form keeps working until keys are added.
 */
function verify_turnstile(?string $token, string $ip): bool
{
    $secret = env_value('TURNSTILE_SECRET_KEY', '');
    if ($secret === null || $secret === '') {
        return true; // Turnstile disabled.
    }
    if (!is_string($token) || $token === '' || !function_exists('curl_init')) {
        return false;
    }

    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => $secret,
            'response' => $token,
            'remoteip' => $ip,
        ]),
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_CONNECTTIMEOUT => 5,
    ]);
    $res = curl_exec($ch);
    curl_close($ch);

    if ($res === false) {
        return false;
    }
    $data = json_decode((string) $res, true);
    return is_array($data) && !empty($data['success']);
}

/* ---------------------------------------------------------------------------
 * Header-injection-safe reply_to
 * ------------------------------------------------------------------------- */
/**
 * Build a safe "Name <email>" reply_to value. Strips CR/LF and control
 * characters from the display name and re-validates the address.
 */
function safe_reply_to(string $name, string $email): string
{
    $email = trim($email);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return '';
    }
    // Remove control chars (incl. CR/LF) and characters that break the header.
    $name = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name) ?? '';
    $name = str_replace(['"', '<', '>', ',', ';', ':', "\r", "\n"], ' ', $name);
    $name = trim(preg_replace('/\s+/u', ' ', $name) ?? '');

    return $name === '' ? $email : sprintf('%s <%s>', $name, $email);
}

/** Strip CR/LF/control characters from a single-line header-ish value. */
function sanitize_header_line(string $value): string
{
    $value = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $value) ?? '';
    return trim(preg_replace('/\s+/u', ' ', $value) ?? '');
}

/* ---------------------------------------------------------------------------
 * Audit logging
 * ------------------------------------------------------------------------- */
/** Append a JSON line to the monthly contact log (for abuse detection). */
function contact_log(array $entry): void
{
    $entry = array_merge(['ts' => date('c')], $entry);
    $line  = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $file  = storage_path('logs') . '/contact-' . date('Y-m') . '.log';
    @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
}
