<?php
/**
 * Task 3 - TRAINING-ONLY web security demo: shared bootstrap.
 *
 * This file boots the deliberately vulnerable application that lives beside
 * its hardened counterpart. Both modes use the SAME fixture data, the SAME
 * SQLite database and the SAME log files, so a demonstration can compare the
 * two implementations side by side.
 *
 * Safety rails (see README):
 *   - binds loopback only (enforced by scripts/run-demo.ps1 and the README);
 *   - SQLite database + log files live under task-3/vulnerable/data/;
 *   - LFI reads are sandboxed to task-3/fixtures/ (never app source or host files);
 *   - all accounts, messages and fixtures are fake training data.
 */

declare(strict_types=1);

date_default_timezone_set('Asia/Kolkata');

define('APP_ROOT', dirname(__DIR__));
define('DATA_DIR', getenv('APEX_DEMO_DATA_DIR') ?: APP_ROOT . '/vulnerable/data');
define('DB_FILE', DATA_DIR . '/demo.sqlite3');
define('SECURITY_LOG', DATA_DIR . '/security.jsonl');
define('ACCESS_LOG', DATA_DIR . '/access.log');
define('FIXTURE_PUBLIC', APP_ROOT . '/fixtures/public');
define('FIXTURE_PRIVATE', APP_ROOT . '/fixtures/private');

const ALLOWED_EVENTS = [
    'auth_success', 'auth_fail', 'auth_lockout',
    'sqli_attempt', 'sqli_blocked',
    'xss_reflected', 'xss_stored', 'xss_blocked',
    'lfi_attempt',
    'csrf_missing', 'csrf_blocked',
    'registration', 'admin_action',
];

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

function ensure_dir(string $dir): void
{
    if (!is_dir($dir) && !mkdir($dir, 0777, true) && !is_dir($dir)) {
        throw new RuntimeException("Cannot create data directory: {$dir}");
    }
}

ensure_dir(DATA_DIR);

/** Append one JSON object as a newline-delimited line, atomically. */
function append_jsonl(string $file, array $row): void
{
    $line = json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($line === false) {
        return;
    }
    file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
}

function client_ip(): string
{
    // Deliberately ignore X-Forwarded-For: this lab has no proxy and a real
    // deployment must not let the client choose its own logged address.
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
}

function request_path(): string
{
    return (string) ($_SERVER['REQUEST_URI'] ?? '/');
}

/**
 * Write one security event in the exact docs/LOG-CONTRACT.md shape.
 * Passing an empty detail omits the optional field.
 */
function log_event(string $event, string $detail = '', ?string $user = null): void
{
    if (!in_array($event, ALLOWED_EVENTS, true)) {
        throw new InvalidArgumentException("Event not in log contract: {$event}");
    }

    $row = [
        'ts' => date('c'),
        'ip' => client_ip(),
        'event' => $event,
        'path' => request_path(),
    ];
    if ($detail !== '') {
        $row['detail'] = mb_substr($detail, 0, 1000);
    }
    if ($user !== null && $user !== '') {
        $row['user'] = mb_substr($user, 0, 120);
    }
    append_jsonl(SECURITY_LOG, $row);
}

// ---------------------------------------------------------------------------
// Database (SQLite, fake local data)
// ---------------------------------------------------------------------------

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA journal_mode = WAL');
    init_db($pdo);
    return $pdo;
}

function init_db(PDO $pdo): void
{
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )'
    );
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS guestbook (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )'
    );

    if ((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() > 0) {
        return;
    }

    $users = [
        ['admin',  'Admin@12345', 'admin@training.local',  'admin'],
        ['demo',   'Demo@12345',  'demo@training.local',   'user'],
        ['analyst','Analyst@123', 'analyst@training.local','auditor'],
        ['intern', 'Intern@123',  'intern@training.local', 'user'],
    ];
    $stmt = $pdo->prepare(
        'INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)'
    );
    foreach ($users as [$name, $password, $email, $role]) {
        // A fast salted-less digest is fine for a training fixture. The point
        // here is SQL injection, not password storage.
        $stmt->execute([$name, hash('sha256', $password), $email, $role]);
    }

    $insert = $pdo->prepare(
        'INSERT INTO guestbook (author, message, created_at) VALUES (?, ?, ?)'
    );
    $insert->execute(['trainer', 'Welcome to the training guestbook. Keep payloads harmless.', date('c')]);
    $insert->execute(['intern', 'Reminder: every account in this database is fake.', date('c')]);
}

function find_user(string $username): ?array
{
    $stmt = db()->prepare('SELECT id, username, email, role FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch();
    return $row === false ? null : $row;
}

function current_user(): array
{
    if (!isset($_SESSION['user'])) {
        // Every visitor of this training lab is the fake "demo" account.
        $_SESSION['user'] = 'demo';
    }
    return find_user((string) $_SESSION['user']) ?? [
        'id' => 0, 'username' => 'demo', 'email' => 'demo@training.local', 'role' => 'user',
    ];
}

// ---------------------------------------------------------------------------
// CSRF helpers (used by the hardened CSRF page)
// ---------------------------------------------------------------------------

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }
    return (string) $_SESSION['csrf_token'];
}

function csrf_valid(?string $token): bool
{
    return is_string($token)
        && $token !== ''
        && isset($_SESSION['csrf_token'])
        && hash_equals((string) $_SESSION['csrf_token'], $token);
}

// ---------------------------------------------------------------------------
// Naive signatures used only for DETECTION (never for sanitisation).
// The hardened pages rely on parameterisation / encoding / token checks; these
// patterns exist so the demo can log and label an attempt in the SIEM.
// ---------------------------------------------------------------------------

function looks_like_sqli(string $value): bool
{
    $patterns = [
        '/\bunion\b[\s\S]{0,40}\bselect\b/i',
        '/\b(or|and)\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i',
        '/[\'"]\s*(--|#|\/\*)/',
        '/;\s*(drop|delete|update|insert|alter)\b/i',
        '/\b(sleep|benchmark|pg_sleep)\s*\(/i',
        '/\b(information_schema|sqlite_master)\b/i',
    ];
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $value) === 1) {
            return true;
        }
    }
    return false;
}

function looks_like_xss(string $value): bool
{
    $patterns = [
        '/<\s*script\b/i',
        '/\bon[a-z]{3,}\s*=/i',
        '/javascript\s*:/i',
        '/<\s*(img|svg|iframe|object|embed|body|video|audio)\b/i',
        '/document\s*\.\s*(cookie|location|write)/i',
        '/\balert\s*\(/i',
    ];
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $value) === 1) {
            return true;
        }
    }
    return false;
}

function looks_like_lfi(string $value): bool
{
    $patterns = [
        '/\.\.[\/\\\\]/',
        '/^(etc|proc|windows|boot|sys)[\/\\\\]/i',
        '/\b(php|data|file|phar|expect):\/\//i',
        '/\b(passwd|boot\.ini|win\.ini|hosts)\b/i',
    ];
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $value) === 1) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// HTML helpers / layout
// ---------------------------------------------------------------------------

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $path): never
{
    header('Location: ' . $path, true, 303);
    exit;
}

function render_page(string $title, string $body, string $active = ''): void
{
    require APP_ROOT . '/app/layout.php';
}

// ---------------------------------------------------------------------------
// Session (fake login state; CSRF token lives here)
// ---------------------------------------------------------------------------

function start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    ensure_dir(DATA_DIR . '/sessions');
    session_save_path(DATA_DIR . '/sessions');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure' => false, // loopback HTTP only; never deployed
    ]);
    session_start();
}
