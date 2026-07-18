<?php
require_once __DIR__ . '/config.php';

const RESET_CODE_LIFETIME_MINUTES = 15;
const RESET_CODE_MAX_ATTEMPTS = 5;
const NEW_PASSWORD_PATTERN = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/';

function clear_password_reset_state(): void
{
    unset(
        $_SESSION['password_reset_email'],
        $_SESSION['password_reset_user_id'],
        $_SESSION['password_reset_verified_at']
    );
}

function send_verification_email(string $recipient, string $code): bool
{
    $subject = 'Your GRC password reset verification code';
    $body = "Your password reset verification code is: {$code}\r\n\r\n"
        . 'This code expires in ' . RESET_CODE_LIFETIME_MINUTES . " minutes.\r\n"
        . 'If you did not request a password reset, please ignore this email.';
    $headers = "From: GRC Login <no-reply@localhost>\r\n"
        . 'Content-Type: text/plain; charset=UTF-8';

    return @mail($recipient, $subject, $body, $headers);
}

function request_reset_code(mysqli $conn, string $email): array
{
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['error' => 'Please enter a valid email address.', 'success' => ''];
    }

    clear_password_reset_state();
    $_SESSION['password_reset_email'] = $email;

    $conn->query(
        'DELETE FROM password_reset_tokens
         WHERE expires_at <= NOW() OR consumed_at IS NOT NULL'
    );

    $stmt = $conn->prepare('SELECT id FROM users WHERE email = ?');
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($user) {
        $stmt = $conn->prepare('DELETE FROM password_reset_tokens WHERE user_id = ?');
        $stmt->bind_param('i', $user['id']);
        $stmt->execute();
        $stmt->close();

        $code = (string) random_int(100000, 999999);
        $codeHash = password_hash($code, PASSWORD_DEFAULT);
        $stmt = $conn->prepare(
            'INSERT INTO password_reset_tokens (user_id, code_hash, expires_at)
             VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE))'
        );
        $stmt->bind_param('is', $user['id'], $codeHash);
        $stmt->execute();
        $stmt->close();

        if (!send_verification_email($email, $code)) {
            error_log('Password reset email delivery failed for user ID ' . $user['id']);
        }
    }

    // The generic response prevents account-email discovery.
    return ['error' => '', 'success' => 'If that email is registered, a verification code has been sent.'];
}

function verify_reset_code(mysqli $conn, string $code): array
{
    if (!preg_match('/^\d{6}$/', $code)) {
        return ['error' => 'Invalid or expired verification code.', 'success' => ''];
    }

    $email = $_SESSION['password_reset_email'] ?? '';
    $stmt = $conn->prepare(
        'SELECT prt.id, prt.user_id, prt.code_hash, prt.attempts
         FROM password_reset_tokens prt
         INNER JOIN users u ON u.id = prt.user_id
         WHERE u.email = ?
           AND prt.consumed_at IS NULL
           AND prt.expires_at > NOW()
         ORDER BY prt.created_at DESC
         LIMIT 1'
    );
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $token = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    $valid = $token
        && (int) $token['attempts'] < RESET_CODE_MAX_ATTEMPTS
        && password_verify($code, $token['code_hash']);

    if (!$valid) {
        if ($token && (int) $token['attempts'] < RESET_CODE_MAX_ATTEMPTS) {
            $stmt = $conn->prepare(
                'UPDATE password_reset_tokens SET attempts = attempts + 1 WHERE id = ?'
            );
            $stmt->bind_param('i', $token['id']);
            $stmt->execute();
            $stmt->close();
        }

        return ['error' => 'Invalid or expired verification code.', 'success' => ''];
    }

    $stmt = $conn->prepare(
        'UPDATE password_reset_tokens
         SET consumed_at = NOW()
         WHERE id = ? AND consumed_at IS NULL'
    );
    $stmt->bind_param('i', $token['id']);
    $stmt->execute();
    $verified = $stmt->affected_rows === 1;
    $stmt->close();

    if (!$verified) {
        return ['error' => 'Invalid or expired verification code.', 'success' => ''];
    }

    session_regenerate_id(true);
    $_SESSION['password_reset_user_id'] = $token['user_id'];
    $_SESSION['password_reset_verified_at'] = time();

    return ['error' => '', 'success' => 'Identity verified. Create your new password.'];
}

function update_password(mysqli $conn, string $password, string $confirmation): array
{
    $userId = (int) ($_SESSION['password_reset_user_id'] ?? 0);
    $verifiedAt = (int) ($_SESSION['password_reset_verified_at'] ?? 0);

    if ($userId < 1 || $verifiedAt < 1
        || time() - $verifiedAt > RESET_CODE_LIFETIME_MINUTES * 60) {
        clear_password_reset_state();
        return [
            'error' => 'Your password reset session has expired. Please request a new code.',
            'success' => '',
            'completed' => false,
        ];
    }

    if (!preg_match(NEW_PASSWORD_PATTERN, $password)) {
        return [
            'error' => 'Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character.',
            'success' => '',
            'completed' => false,
        ];
    }

    if ($password !== $confirmation) {
        return [
            'error' => 'The password confirmation does not match.',
            'success' => '',
            'completed' => false,
        ];
    }

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    $conn->begin_transaction();

    try {
        $stmt = $conn->prepare(
            'UPDATE users
             SET password_hash = ?, failed_attempts = 0, locked_until = NULL
             WHERE id = ?'
        );
        $stmt->bind_param('si', $passwordHash, $userId);
        $stmt->execute();
        $updated = $stmt->affected_rows === 1;
        $stmt->close();

        if (!$updated) {
            throw new RuntimeException('The password reset account no longer exists.');
        }

        $stmt = $conn->prepare('DELETE FROM password_reset_tokens WHERE user_id = ?');
        $stmt->bind_param('i', $userId);
        $stmt->execute();
        $stmt->close();
        $conn->commit();
    } catch (Throwable $exception) {
        $conn->rollback();
        error_log('Password reset failed: ' . $exception->getMessage());
        return [
            'error' => 'Unable to reset your password. Please try again.',
            'success' => '',
            'completed' => false,
        ];
    }

    clear_password_reset_state();
    return [
        'error' => '',
        'success' => 'Your password has been reset. You can now log in with your new password.',
        'completed' => true,
    ];
}

$error = '';
$success = '';
$completed = false;

if (empty($_SESSION['forgot_password_csrf'])) {
    $_SESSION['forgot_password_csrf'] = bin2hex(random_bytes(32));
}

if (isset($_SESSION['password_reset_verified_at'])
    && time() - (int) $_SESSION['password_reset_verified_at'] > RESET_CODE_LIFETIME_MINUTES * 60) {
    clear_password_reset_state();
    $error = 'Your password reset session has expired. Please request a new code.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['forgot_password_csrf'], $csrfToken)) {
        $error = 'Your request could not be verified. Please try again.';
    } else {
        switch ($_POST['action'] ?? '') {
            case 'restart':
                clear_password_reset_state();
                redirect_to('forgot-password.php');

            case 'request_code':
                $result = request_reset_code($conn, trim($_POST['email'] ?? ''));
                break;

            case 'verify_code':
                $result = verify_reset_code($conn, trim($_POST['verification_code'] ?? ''));
                break;

            case 'reset_password':
                $result = update_password(
                    $conn,
                    $_POST['new_password'] ?? '',
                    $_POST['confirm_password'] ?? ''
                );
                break;

            default:
                $result = ['error' => '', 'success' => ''];
        }

        if (isset($result)) {
            $error = $result['error'];
            $success = $result['success'];
            $completed = $result['completed'] ?? false;
        }
    }
}

$step = 'request';
if ($completed) {
    $step = 'complete';
} elseif (!empty($_SESSION['password_reset_user_id']) && !empty($_SESSION['password_reset_verified_at'])) {
    $step = 'reset';
} elseif (!empty($_SESSION['password_reset_email'])) {
    $step = 'verify';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - Global Reciprocal Colleges</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
<div class="log">
    <div class="login-header">
        <div class="logo-container">
            <img src="https://raw.githubusercontent.com/jiem10/Login/main/download.png" alt="Global Reciprocal Colleges logo" class="logo-img">
        </div>
        <div class="welcome-text">
            <h3>Forgot Password</h3>
            <p>Verify your identity to create a new password.</p>
        </div>
    </div>

    <?php if ($error !== ''): ?>
        <div class="message"><?= escape($error) ?></div>
    <?php endif; ?>
    <?php if ($success !== ''): ?>
        <div class="message success-message"><?= escape($success) ?></div>
    <?php endif; ?>

    <?php if ($step === 'request'): ?>
        <form action="forgot-password.php" method="POST">
            <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['forgot_password_csrf']) ?>">
            <input type="hidden" name="action" value="request_code">
            <div class="input-group">
                <label for="email">Registered Email Address</label>
                <div class="input-wrapper">
                    <i class="fa-regular fa-envelope input-icon"></i>
                    <input type="email" name="email" id="email" placeholder="Enter your registered email" required autocomplete="email">
                </div>
            </div>
            <button type="submit" class="btn-primary">Send Verification Code</button>
        </form>
    <?php elseif ($step === 'verify'): ?>
        <form action="forgot-password.php" method="POST">
            <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['forgot_password_csrf']) ?>">
            <input type="hidden" name="action" value="verify_code">
            <div class="input-group">
                <label for="verification_code">Verification Code</label>
                <div class="input-wrapper">
                    <i class="fa-solid fa-shield-halved input-icon"></i>
                    <input type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" name="verification_code" id="verification_code" placeholder="Enter the 6-digit code" required autocomplete="one-time-code">
                </div>
            </div>
            <button type="submit" class="btn-primary">Verify Identity</button>
        </form>
        <form action="forgot-password.php" method="POST" class="secondary-action-form">
            <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['forgot_password_csrf']) ?>">
            <input type="hidden" name="action" value="restart">
            <button type="submit" class="text-button">Use a different email</button>
        </form>
    <?php elseif ($step === 'reset'): ?>
        <form action="forgot-password.php" method="POST">
            <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['forgot_password_csrf']) ?>">
            <input type="hidden" name="action" value="reset_password">
            <div class="input-group">
                <label for="new_password">New Password</label>
                <div class="input-wrapper">
                    <i class="fa-solid fa-lock input-icon"></i>
                    <input type="password" name="new_password" id="new_password" placeholder="Create a new password" required autocomplete="new-password">
                    <i class="fa-regular fa-eye toggle-password" data-password-target="new_password"></i>
                </div>
            </div>
            <div class="password-requirements">Use 8+ characters with uppercase, lowercase, a number, and a special character.</div>
            <div class="input-group">
                <label for="confirm_password">Confirm New Password</label>
                <div class="input-wrapper">
                    <i class="fa-solid fa-lock input-icon"></i>
                    <input type="password" name="confirm_password" id="confirm_password" placeholder="Confirm your new password" required autocomplete="new-password">
                    <i class="fa-regular fa-eye toggle-password" data-password-target="confirm_password"></i>
                </div>
            </div>
            <button type="submit" class="btn-primary">Reset Password</button>
        </form>
    <?php else: ?>
        <form action="login.php" method="GET">
            <button type="submit" class="btn-primary">Go to Login</button>
        </form>
    <?php endif; ?>

    <?php if ($step !== 'complete'): ?>
        <div class="footer-text">
            Remembered your password? <a href="login.php">Back to Login</a>
        </div>
    <?php endif; ?>
</div>

<script>
    document.querySelectorAll('[data-password-target]').forEach((toggle) => {
        toggle.addEventListener('click', () => {
            const input = document.getElementById(toggle.dataset.passwordTarget);
            const hidden = input.type === 'password';
            input.type = hidden ? 'text' : 'password';
            toggle.classList.toggle('fa-eye-slash', hidden);
        });
    });
</script>
</body>
</html>
