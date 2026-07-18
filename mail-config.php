<?php
$env = static function (string $name, string $default = ''): string {
    $value = getenv($name);
    return $value === false ? $default : $value;
};

$config = [
    'host' => $env('SMTP_HOST'),
    'port' => (int) $env('SMTP_PORT', '587'),
    'encryption' => $env('SMTP_ENCRYPTION', 'tls'),
    'username' => $env('SMTP_USERNAME'),
    'password' => $env('SMTP_PASSWORD'),
    'from_email' => $env('SMTP_FROM_EMAIL', $env('SMTP_USERNAME')),
    'from_name' => $env('SMTP_FROM_NAME', 'GRC Login'),
    // This is additionally restricted to requests from 127.0.0.1 or ::1.
    'show_code_on_localhost' => filter_var(
        $env('MAIL_SHOW_LOCAL_CODE', 'false'),
        FILTER_VALIDATE_BOOLEAN
    ),
];

$localConfigPath = __DIR__ . '/mail-config.local.php';
if (is_file($localConfigPath)) {
    $localConfig = require $localConfigPath;
    if (is_array($localConfig)) {
        $config = array_replace($config, $localConfig);
    }
}

return $config;
