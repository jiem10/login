<?php
require_once __DIR__ . '/config.php';

const RESET_CODE_LIFETIME_MINUTES = 15;
const RESET_CODE_MAX_ATTEMPTS = 5;

function clear_password_reset_state(): void
{
    unset(
        $_SESSION['password_reset_email'],
        $_SESSION['password_reset_user_id'],
        $_SESSION['password_reset_verified_at']
    );
}

function request_reset_code(mysqli $conn, string $email): array
{
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['error' => 'Please enter a valid email address.', 'success' => ''];
    }

    clear_password_reset_state();

    $conn->query(
        'DELETE FROM password_reset_tokens
         WHERE expires_at <= NOW() OR consumed_at IS NOT NULL'
    );

    $stmt = $conn->prepare('SELECT id FROM users WHERE email = ?');
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user) {
        return ['error' => 'No account was found with that email address.', 'success' => ''];
    }

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

    $_SESSION['password_reset_email'] = $email;

    return [
        'error' => '',
        'success' => 'Your verification code is ' . $code . '. It expires in 15 minutes.',
    ];
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

    if (!password_is_valid($password)) {
        return [
            'error' => PASSWORD_REQUIREMENTS,
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
            <img src="https://i.imgur.com/u75GA9x.png" alt="Global Reciprocal Colleges logo" class="logo-img">
        </div>
        <div class="welcome-text">
            <h3>Forgot Password</h3>
            <p>Generate a verification code to create a new password.</p>
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
            <button type="submit" class="btn-primary">Generate Verification Code</button>
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
                    <input type="password" name="new_password" id="new_password" placeholder="Create a new password" required minlength="8" pattern="(?=.*[A-Z])(?=.*[^A-Za-z0-9\s.,]).{8,}" title="Use at least 8 characters with an uppercase letter and a special symbol other than a period or comma." autocomplete="new-password">
                    <i class="fa-regular fa-eye toggle-password" data-password-target="new_password"></i>
                </div>
            </div>
            <div class="password-strength" data-password-strength data-password-input="new_password" aria-live="polite">
                <div class="password-strength-track">
                    <div class="password-strength-bar" data-strength-bar role="progressbar" aria-label="Password strength" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"></div>
                </div>
                <div class="password-strength-details">
                    <span data-strength-label>Enter a password</span>
                    <span data-length-label>0/8 characters</span>
                </div>
                <div class="password-requirements" aria-label="Password requirements">
                    <span class="password-requirement" data-requirement-length>At least 8 characters</span>
                    <span class="password-requirement" data-requirement-uppercase>One uppercase letter</span>
                    <span class="password-requirement" data-requirement-symbol>One special symbol (!, @, #, $, %, &amp;, or *); periods and commas do not count</span>
                </div>
            </div>
            <div class="input-group">
                <label for="confirm_password">Confirm New Password</label>
                <div class="input-wrapper">
                    <i class="fa-solid fa-lock input-icon"></i>
                    <input type="password" name="confirm_password" id="confirm_password" placeholder="Confirm your new password" required autocomplete="new-password" data-password-confirm-for="new_password" data-password-match-message="reset-password-match" aria-describedby="reset-password-match">
                    <i class="fa-regular fa-eye toggle-password" data-password-target="confirm_password"></i>
                </div>
                <div id="reset-password-match" class="password-match-feedback" data-password-match-feedback aria-live="polite"></div>
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
        if (!input) return;
        const hidden = input.type === 'password';
        input.type = hidden ? 'text' : 'password';
        toggle.classList.toggle('fa-eye-slash', hidden);
    });
});

document.querySelectorAll('[data-password-strength]').forEach((meter) => {
    const input = document.getElementById(meter.dataset.passwordInput);
    const bar = meter.querySelector('[data-strength-bar]');
    const label = meter.querySelector('[data-strength-label]');
    const lengthLabel = meter.querySelector('[data-length-label]');
    const requirements = {
        length: meter.querySelector('[data-requirement-length]'),
        uppercase: meter.querySelector('[data-requirement-uppercase]'),
        symbol: meter.querySelector('[data-requirement-symbol]'),
    };
    if (!input || !bar || !label || !lengthLabel || Object.values(requirements).some((item) => !item)) return;

    const update = () => {
        const password = input.value;
        const checks = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            symbol: /[^A-Za-z0-9\s.,]/.test(password),
        };
        const score = Object.values(checks).filter(Boolean).length;
        Object.keys(checks).forEach((key) => requirements[key].classList.toggle('met', checks[key]));
        bar.className = 'password-strength-bar';

        if (password === '') {
            bar.style.width = '0';
            label.textContent = 'Enter a password';
            bar.setAttribute('aria-valuenow', '0');
        } else if (score === 1) {
            bar.classList.add('weak');
            bar.style.width = '33%';
            label.textContent = 'Weak';
            bar.setAttribute('aria-valuenow', '33');
        } else if (score === 2) {
            bar.classList.add('medium');
            bar.style.width = '66%';
            label.textContent = 'Almost secure';
            bar.setAttribute('aria-valuenow', '66');
        } else if (score === 3) {
            bar.classList.add('strong');
            bar.style.width = '100%';
            label.textContent = 'Strong and secure';
            bar.setAttribute('aria-valuenow', '100');
        } else {
            bar.classList.add('weak');
            bar.style.width = '15%';
            label.textContent = 'Weak';
            bar.setAttribute('aria-valuenow', '15');
        }
        lengthLabel.textContent = `${password.length}/8 characters`;
    };

    input.addEventListener('input', update);
    update();
});

document.querySelectorAll('[data-password-confirm-for]').forEach((confirmation) => {
    const password = document.getElementById(confirmation.dataset.passwordConfirmFor);
    const feedback = document.getElementById(confirmation.dataset.passwordMatchMessage);
    if (!password || !feedback) return;

    const update = () => {
        feedback.className = 'password-match-feedback';
        if (confirmation.value === '') {
            feedback.textContent = '';
            confirmation.setCustomValidity('');
            confirmation.removeAttribute('aria-invalid');
        } else if (password.value === confirmation.value) {
            feedback.classList.add('match');
            feedback.textContent = 'Passwords match.';
            confirmation.setCustomValidity('');
            confirmation.setAttribute('aria-invalid', 'false');
        } else {
            feedback.classList.add('mismatch');
            feedback.textContent = 'Passwords do not match.';
            confirmation.setCustomValidity('Passwords do not match.');
            confirmation.setAttribute('aria-invalid', 'true');
        }
    };

    password.addEventListener('input', update);
    confirmation.addEventListener('input', update);
    update();
});
</script>
</body>
</html>
