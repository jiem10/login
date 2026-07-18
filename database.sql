CREATE DATABASE IF NOT EXISTS login_module_db;
USE login_module_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_number VARCHAR(20) NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Keep older imports compatible with the current lockout fields.
UPDATE users SET failed_attempts = 0 WHERE failed_attempts IS NULL;
ALTER TABLE users MODIFY failed_attempts INT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_password_reset_user_expiry (user_id, expires_at),
    CONSTRAINT fk_password_reset_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS login_attempts;

INSERT INTO users (student_number, email, password_hash)
VALUES ('2026-07-00256', 'jiem10@gmail.com', '$2y$12$m41apc2GYjBOFpXjTCgI8uBDiKkhQBcJtB4W6XgbKj21DVyzAJjgS')
ON DUPLICATE KEY UPDATE
    student_number = '2026-07-00256',
    password_hash = '$2y$12$m41apc2GYjBOFpXjTCgI8uBDiKkhQBcJtB4W6XgbKj21DVyzAJjgS';
