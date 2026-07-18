<?php
const SESSION_TIMEOUT_SECONDS = 900;

function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

function session_has_expired(): bool
{
    return isset($_SESSION['LAST_ACTIVITY'])
        && time() - (int) $_SESSION['LAST_ACTIVITY'] > SESSION_TIMEOUT_SECONDS;
}

function end_session(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }

    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $cookie = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $cookie['path'],
            'domain' => $cookie['domain'],
            'secure' => $cookie['secure'],
            'httponly' => $cookie['httponly'],
            'samesite' => $cookie['samesite'] ?? 'Lax',
        ]);
    }

    session_destroy();
}

function redirect_to(string $location): void
{
    header('Location: ' . $location);
    exit;
}

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

start_secure_session();

mysqli_report(MYSQLI_REPORT_OFF);
$conn = @new mysqli('localhost', 'root', '', 'login_module_db');

if ($conn->connect_errno) {
    http_response_code(503);
    exit('Database connection failed. Make sure MySQL is running in XAMPP and database.sql has been imported.');
}

$conn->set_charset('utf8mb4');
