CREATE DATABASE IF NOT EXISTS login_module_db=;
USE login_module_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_number VARCHAR(20) NULL UNIQUE,
    full_name VARCHAR(100) NOT NULL,
    queue_status ENUM('waiting', 'serving', 'served') NOT NULL DEFAULT 'waiting',
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(100) NULL AFTER student_number;
ALTER TABLE users ADD COLUMN IF NOT EXISTS queue_status ENUM('waiting', 'serving', 'served') NOT NULL DEFAULT 'waiting' AFTER full_name;
UPDATE users SET full_name = CONCAT('Student ', id) WHERE full_name IS NULL OR TRIM(full_name) = '';
ALTER TABLE users MODIFY full_name VARCHAR(100) NOT NULL;
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

INSERT INTO users (student_number, full_name, email, password_hash, queue_status)
VALUES ('2024-07-00259', 'John Mark Bandico', 'jugan.johnmark.bandico@gmail.com', '$2y$10$6k.9KUuzBfBFdNVdx0OHiOgO0A96Z3Q6yuAzxbsM.LwmL7FZjreoW', 'waiting')
ON DUPLICATE KEY UPDATE
    student_number = '2024-07-00259',
    full_name = 'John Mark Bandico',
    password_hash = '$2y$10$6k.9KUuzBfBFdNVdx0OHiOgO0A96Z3Q6yuAzxbsM.LwmL7FZjreoW';

INSERT INTO users (student_number, full_name, email, password_hash, queue_status, created_at)
VALUES
    ('2024-07-00101', 'Maria Santos', 'maria.santos101@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'served', CONCAT(CURDATE(), ' 09:35:00')),
    ('2024-07-00102', 'Paul Villanueva', 'paul.villanueva102@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'served', CONCAT(CURDATE(), ' 09:41:00')),
    ('2024-07-00103', 'John Dela Cruz', 'john.delacruz103@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'serving', CONCAT(CURDATE(), ' 09:53:00')),
    ('2024-07-00104', 'Luis Hernandez', 'luis.hernandez104@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'waiting', CONCAT(CURDATE(), ' 09:57:00')),
    ('2024-07-00105', 'Jane Cruz', 'jane.cruz105@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'waiting', CONCAT(CURDATE(), ' 10:01:00')),
    ('2024-07-00106', 'Mark Reyes', 'mark.reyes106@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'waiting', CONCAT(CURDATE(), ' 10:07:00')),
    ('2024-07-00107', 'Anna Santos', 'anna.santos107@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'waiting', CONCAT(CURDATE(), ' 10:15:00')),
    ('2024-07-00108', 'Carla Mendoza', 'carla.mendoza108@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'waiting', CONCAT(CURDATE(), ' 10:22:00')),
    ('2024-07-00109', 'Joshua Garcia', 'joshua.garcia109@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'waiting', CONCAT(CURDATE(), ' 10:28:00')),
    ('2024-07-00110', 'Sofia Ramos', 'sofia.ramos110@example.test', '$2y$10$mc2st7EMehHUxJKw.79U2.Kcgh66818FN8CogetzkwdcWLbwx1DS.', 'waiting', CONCAT(CURDATE(), ' 10:34:00'))
ON DUPLICATE KEY UPDATE
    full_name = VALUES(full_name),
    queue_status = VALUES(queue_status),
    created_at = VALUES(created_at);