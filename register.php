<?php
require_once __DIR__ . '/config.php';

if (isset($_SESSION['user_id'])) {
    redirect_to('dashboard.php');
}

if (empty($_SESSION['register_csrf'])) {
    $_SESSION['register_csrf'] = bin2hex(random_bytes(32));
}

$error = '';
$studentNumber = '';
$fullName = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = (string) ($_POST['csrf_token'] ?? '');
    $studentNumber = trim((string) ($_POST['student_number'] ?? ''));
    $fullName = preg_replace('/\s+/u', ' ', trim((string) ($_POST['full_name'] ?? ''))) ?? '';
    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $password = (string) ($_POST['password'] ?? '');
    $confirmation = (string) ($_POST['confirm_password'] ?? '');
    $fullNameLength = function_exists('mb_strlen')
        ? mb_strlen($fullName, 'UTF-8')
        : strlen($fullName);

    if (!hash_equals($_SESSION['register_csrf'], $csrfToken)) {
        $error = 'Your request could not be verified. Please refresh the page and try again.';
    } elseif (!preg_match('/^\d{4}-\d{2}-\d{5}$/', $studentNumber)) {
        $error = 'Enter a valid student number in the format 2026-07-00256.';
    } elseif ($fullNameLength < 2 || $fullNameLength > 100
        || !preg_match("/^[\p{L}\p{M}][\p{L}\p{M}' .-]*$/u", $fullName)) {
        $error = 'Enter a valid full name using letters, spaces, apostrophes, periods, or hyphens.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
        $error = 'Please enter a valid email address.';
    } elseif (!password_is_valid($password)) {
        $error = PASSWORD_REQUIREMENTS;
    } elseif ($password !== $confirmation) {
        $error = 'The password confirmation does not match.';
    } else {
        $stmt = $conn->prepare(
            'SELECT email, student_number FROM users WHERE email = ? OR student_number = ? LIMIT 1'
        );
        $stmt->bind_param('ss', $email, $studentNumber);
        $stmt->execute();
        $existingUser = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if ($existingUser) {
            $error = hash_equals((string) $existingUser['email'], $email)
                ? 'An account already exists with that email address.'
                : 'An account already exists with that student number.';
        } else {
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare(
                'INSERT INTO users (student_number, full_name, email, password_hash) VALUES (?, ?, ?, ?)'
            );
            $stmt->bind_param('ssss', $studentNumber, $fullName, $email, $passwordHash);
            $created = $stmt->execute();
            $databaseError = $stmt->errno;
            $stmt->close();

            if ($created) {
                unset($_SESSION['register_csrf']);
                $_SESSION['login_success'] = 'Account created successfully. You can now log in.';
                redirect_to('login.php');
            }

            $error = $databaseError === 1062
                ? 'An account already exists with that email address or student number.'
                : 'Unable to create your account right now. Please try again.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account - Global Reciprocal Colleges</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
<div class="log">
    <div class="login-header">
        <div class="logo-container">
            <img src="https://i.imgur.com/u75GA9x.png" alt="Global Reciprocal Colleges logo" class="logo-img">
        </div>
        <div class="welcome-text auth-heading">
            <h3>Create an Account</h3>
            <p>Enter your student details to register.</p>
        </div>
    </div>

    <?php if ($error !== ''): ?>
        <div class="message"><?= escape($error) ?></div>
    <?php endif; ?>

    <form action="register.php" method="POST">
        <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['register_csrf']) ?>">
        <div class="input-group">
            <label for="student_number">Student Number</label>
            <div class="input-wrapper">
                <i class="fa-solid fa-id-card input-icon"></i>
                <input type="text" name="student_number" id="student_number" placeholder="e.g. 2026-07-00256" pattern="[0-9]{4}-[0-9]{2}-[0-9]{5}" title="Format: 2026-07-00256" required autocomplete="username" value="<?= escape($studentNumber) ?>">
            </div>
        </div>
        <div class="input-group">
            <label for="full_name">Full Name</label>
            <div class="input-wrapper">
                <i class="fa-regular fa-user input-icon"></i>
                <input type="text" name="full_name" id="full_name" placeholder="Enter your full name" required minlength="2" maxlength="100" autocomplete="name" value="<?= escape($fullName) ?>">
            </div>
        </div>
        <div class="input-group">
            <label for="email">Email Address</label>
            <div class="input-wrapper">
                <i class="fa-regular fa-envelope input-icon"></i>
                <input type="email" name="email" id="email" placeholder="Enter your email" required autocomplete="email" maxlength="255" value="<?= escape($email) ?>">
            </div>
        </div>
        <div class="input-group">
            <label for="password">Password</label>
            <div class="input-wrapper">
                <i class="fa-solid fa-lock input-icon"></i>
                <input type="password" name="password" id="password" placeholder="Create a password" required minlength="8" pattern="(?=.*[A-Z])(?=.*[^A-Za-z0-9\s.,]).{8,}" title="Use at least 8 characters with an uppercase letter and a special symbol other than a period or comma." autocomplete="new-password">
                <i class="fa-regular fa-eye toggle-password" data-password-target="password"></i>
            </div>
        </div>
        <div class="password-strength" data-password-strength data-password-input="password" aria-live="polite">
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
            <label for="confirm_password">Confirm Password</label>
            <div class="input-wrapper">
                <i class="fa-solid fa-lock input-icon"></i>
                <input type="password" name="confirm_password" id="confirm_password" placeholder="Confirm your password" required autocomplete="new-password" data-password-confirm-for="password" data-password-match-message="register-password-match" aria-describedby="register-password-match">
                <i class="fa-regular fa-eye toggle-password" data-password-target="confirm_password"></i>
            </div>
            <div id="register-password-match" class="password-match-feedback" aria-live="polite"></div>
        </div>
        <button type="submit" class="btn-primary">Create Account</button>
    </form>

    <div class="footer-text">
        Already have an account? <a href="login.php">Back to Login</a>
    </div>
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
