<?php
/**
 * Task 3 front controller.
 *
 * Start with:
 *   php -d extension=pdo_sqlite -S 127.0.0.1:8091 -t task-3/public task-3/public/router.php
 *
 * Every request is logged to task-3/vulnerable/data/access.log in the shape
 * documented in docs/LOG-CONTRACT.md. Security events are written by the pages.
 */

declare(strict_types=1);

$__started = hrtime(true);

require dirname(__DIR__) . '/app/bootstrap.php';
start_session();

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header('X-Frame-Options: DENY');

// Access log is written at shutdown so the final status code is known.
register_shutdown_function(static function () use ($__started): void {
    $status = http_response_code();
    if (!is_int($status) || $status < 100) {
        $status = 200;
    }
    $row = [
        'ts' => date('c'),
        'ip' => client_ip(),
        'method' => (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'),
        'path' => request_path(),
        'status' => $status,
        'ua' => mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? '-'), 0, 300),
        'dur_ms' => (int) round((hrtime(true) - $__started) / 1_000_000),
    ];
    append_jsonl(ACCESS_LOG, $row);
});

$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
$path = is_string($path) ? $path : '/';
if ($path !== '/') {
    $path = rtrim($path, '/');
}

$routes = [
    '/' => ['home.php', 'home', null],
    '/vuln/sqli' => ['sqli.php', 'vuln-sqli', 'vuln'],
    '/secure/sqli' => ['sqli.php', 'secure-sqli', 'secure'],
    '/vuln/xss' => ['xss.php', 'vuln-xss', 'vuln'],
    '/secure/xss' => ['xss.php', 'secure-xss', 'secure'],
    '/vuln/csrf' => ['csrf.php', 'vuln-csrf', 'vuln'],
    '/secure/csrf' => ['csrf.php', 'secure-csrf', 'secure'],
    '/vuln/lfi' => ['lfi.php', 'vuln-lfi', 'vuln'],
    '/secure/lfi' => ['lfi.php', 'secure-lfi', 'secure'],
];

$route = $routes[$path] ?? null;
if ($route === null) {
    http_response_code(404);
    render_page('Not found', '<div class="card"><h2 style="margin-top:0">404</h2><p>No such training route: <code>' . e($path) . '</code></p><p><a href="/">Back to the overview</a></p></div>');
    return;
}

[$file, $active, $mode] = $route;
$MODE = $mode;              // 'vuln' | 'secure' | null
$ACTIVE = $active;
$METHOD = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');

require APP_ROOT . '/app/pages/' . $file;
