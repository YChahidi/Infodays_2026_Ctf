-- MariaDB init for YAMI SUKEHIRO mana reservation system
-- Idempotent: safe to re-run

CREATE DATABASE IF NOT EXISTS mana_db;
USE mana_db;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password CHAR(64) NOT NULL,
  role_id VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS appointments (
  appointment_id INT AUTO_INCREMENT PRIMARY KEY,
  appointment_name VARCHAR(255) NOT NULL,
  appointment_email VARCHAR(255) NOT NULL,
  appointment_date DATE NOT NULL,
  appointment_time TIME NOT NULL,
  appointment_people INT NOT NULL,
  appointment_message TEXT,
  role_id VARCHAR(64) NOT NULL DEFAULT 'knight'
);

-- Seed: Captain Yami account (the captain/admin). Password unknown to attacker.
INSERT IGNORE INTO users (email, password, role_id) VALUES
  ('yami.sukehiro@black-bulls.lab',
   SHA2(CONCAT('dark_magic_', RAND()), 256),
   'captain');

-- Seed a few demo reservations
INSERT IGNORE INTO appointments
  (appointment_id, appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message, role_id)
VALUES
  (1, 'Asta', 'asta@black-bulls.lab', '2026-05-01', '09:00:00', 1, 'Anti-magic training', 'knight'),
  (2, 'Noelle Silva', 'noelle@black-bulls.lab', '2026-05-02', '14:30:00', 1, 'Water magic session', 'knight'),
  (3, 'Magna Swing', 'magna@black-bulls.lab', '2026-05-03', '18:00:00', 3, 'Fire magic group', 'knight');

-- Application DB user: MUST have FILE privilege (the vulnerability)
CREATE USER IF NOT EXISTS 'yuno'@'localhost' IDENTIFIED BY '3wDo7gSRZIwIHRxZ!';
GRANT SELECT, INSERT, UPDATE, DELETE ON mana_db.* TO 'yuno'@'localhost';
GRANT FILE ON *.* TO 'yuno'@'localhost';
FLUSH PRIVILEGES;
