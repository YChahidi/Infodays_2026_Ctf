-- BATISTUTA scouting platform — init
-- Two DBs: `phishing` (victims), `temp` (command_log with timestamp attacker must recover)

CREATE DATABASE IF NOT EXISTS phishing;
USE phishing;

CREATE TABLE IF NOT EXISTS victims (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  phishing_score INT NOT NULL
);

INSERT IGNORE INTO victims (id, email, phishing_score) VALUES
  (1, 'striker1@club.lab', 20),
  (2, 'striker2@club.lab', 40),
  (3, 'striker3@club.lab', 60),
  (4, 'defender1@club.lab', 80),
  (5, 'keeper@club.lab', 100);

CREATE DATABASE IF NOT EXISTS temp;
USE temp;

CREATE TABLE IF NOT EXISTS command_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  date DATETIME NOT NULL,
  command TEXT NOT NULL
);

-- Rows 1–4 are harmless decoys. Row 5 leaks the restic URL + password (needed
-- for user flag). Row 6 will be updated by entrypoint.sh with the real boot
-- timestamp (seed for the batistuta password generator = root flag gate).
INSERT IGNORE INTO command_log (id, date, command) VALUES
  (1, '2024-08-30 10:44:01', 'uname -a'),
  (2, '2024-08-30 11:58:05', 'restic init --repo rest:http://localhost/restic'),
  (3, '2024-08-30 11:58:36', 'echo r0ck_y0u_cr@ck_m3_2025 > .restic_passwd'),
  (4, '2024-08-30 11:59:02', 'rm -rf .bash_history'),
  (5, '2024-08-30 11:59:47', '# backup at /restic/backup.7z — pw in line 3'),
  (6, '2024-08-30 14:40:42', 'cd /home/batistuta/ && /opt/bin/batistuta-pwgen | passwd');

-- Application DB user — SELECT only (no FILE needed here, SQLi exfil is blind/error).
CREATE USER IF NOT EXISTS 'n8n'@'localhost' IDENTIFIED BY '3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS';
GRANT SELECT ON phishing.* TO 'n8n'@'localhost';
GRANT SELECT ON temp.*     TO 'n8n'@'localhost';
GRANT UPDATE ON temp.*     TO 'n8n'@'localhost';
FLUSH PRIVILEGES;
