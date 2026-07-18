<?php
require_once __DIR__ . '/config.php';

function find_login_user(mysqli $conn, string $email): ?array
{
    $stmt = $conn->prepare(
        "SELECT id, email, student_number, password_hash, failed_attempts,
                (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked,
                (locked_until IS NOT NULL AND locked_until <= NOW()) AS lock_expired
         FROM users
         WHERE email = ?"
    );
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc() ?: null;
    $stmt->close();

    return $user;
}

function clear_login_failures(mysqli $conn, int $userId): void
{
    $stmt = $conn->prepare(
        'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?'
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $stmt->close();
}

function record_login_failure(mysqli $conn, int $userId): int
{
    $stmt = $conn->prepare(
        "UPDATE users
         SET failed_attempts = failed_attempts + 1,
             locked_until = CASE
                 WHEN failed_attempts + 1 >= 5 THEN DATE_ADD(NOW(), INTERVAL 30 MINUTE)
                 ELSE NULL
             END
         WHERE id = ?"
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $stmt->close();

    $stmt = $conn->prepare('SELECT failed_attempts FROM users WHERE id = ?');
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $attempts = (int) ($stmt->get_result()->fetch_assoc()['failed_attempts'] ?? 0);
    $stmt->close();

    return $attempts;
}

$error = '';
$success = (string) ($_SESSION['login_success'] ?? '');
unset($_SESSION['login_success']);

if (session_has_expired()) {
    end_session();
    start_secure_session();
    $error = 'Session expired. Please log in again.';
}

if (isset($_SESSION['user_id']) && $error === '') {
    redirect_to('dashboard.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $studentNumber = trim($_POST['student_number'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($studentNumber === '' || $email === '' || $password === '') {
        $error = 'Please enter both username and password.';
    } else {
        $user = find_login_user($conn, $email);

        if ($user && (int) $user['lock_expired'] === 1) {
            clear_login_failures($conn, (int) $user['id']);
            $user['failed_attempts'] = 0;
            $user['is_locked'] = 0;
        }

        $credentialsValid = $user
            && password_verify($password, $user['password_hash'])
            && hash_equals((string) $user['student_number'], $studentNumber);

        if ($user && (int) $user['is_locked'] === 1) {
            $error = 'Your account has been locked due to multiple failed login attempts.';
        } elseif ($credentialsValid) {
            clear_login_failures($conn, (int) $user['id']);
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['LAST_ACTIVITY'] = time();
            redirect_to('dashboard.php');
        } elseif ($user) {
            $attempts = record_login_failure($conn, (int) $user['id']);
            $error = $attempts >= 5
                ? 'Your account has been locked due to multiple failed login attempts.'
                : 'Invalid username or password.';
        } else {
            $error = 'Invalid username or password.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Global Reciprocal Colleges</title>
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
            <h3>Login</h3>
            <p>Welcome back! Please login to your account.</p>
        </div>
    </div>

    <?php if ($error !== ''): ?>
        <div class="message"><?= escape($error) ?></div>
    <?php endif; ?>
    <?php if ($success !== ''): ?>
        <div class="message success-message"><?= escape($success) ?></div>
    <?php endif; ?>

    <form action="login.php" method="POST">
        <div class="input-group">
            <label for="student_number">Student Number</label>
            <div class="input-wrapper">
                <i class="fa-solid fa-id-card input-icon"></i>
                <input type="text" name="student_number" id="student_number" placeholder="e.g. 2026-07-00256" pattern="[0-9]{4}-[0-9]{2}-[0-9]{5}" title="Format: 2026-07-00256" required value="<?= escape(trim($_POST['student_number'] ?? '')) ?>">
            </div>
        </div>
        <div class="input-group">
            <label for="email">Email Address</label>
            <div class="input-wrapper">
                <i class="fa-regular fa-envelope input-icon"></i>
                <input type="email" name="email" id="email" placeholder="Enter your email" required value="<?= escape(trim($_POST['email'] ?? '')) ?>">
            </div>
        </div>
        <div class="input-group">
            <label for="password">Password</label>
            <div class="input-wrapper">
                <i class="fa-solid fa-lock input-icon"></i>
                <input type="password" name="password" id="password" placeholder="Enter your password" required>
                <i class="fa-regular fa-eye toggle-password" id="togglePassword"></i>
            </div>
        </div>
        <div class="options-row">
            <a href="forgot-password.php">Forgot Password?</a>
        </div>
        <button type="submit" class="btn-primary">Login</button>
        <div class="divider"><span>OR</span></div>
        <a href="register.php" class="btn-secondary" id="createAccount">
            <i class="fa-regular fa-user"></i> Create an account
        </a>
        <div class="footer-text">
            Don't have an account? <a href="register.php">Register here</a>
        </div>
    </form>
</div>

<script>
    const passwordInput = document.getElementById('password');
    const passwordToggle = document.getElementById('togglePassword');

    passwordToggle.addEventListener('click', () => {
        const hidden = passwordInput.type === 'password';
        passwordInput.type = hidden ? 'text' : 'password';
        passwordToggle.classList.toggle('fa-eye-slash', hidden);
    });
</script>
</body>
</html>
