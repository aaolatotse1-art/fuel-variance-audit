-- =============================================================
--  Sky Bridge Logistics — Fuel Variance Audit
--  MySQL 8.0+ Schema + Seed Data
--  Generated: 2026-06-20
--
--  IMPORTANT: Passwords are seeded with SHA2-256 as a temporary
--  placeholder.  Before going to production, migrate to bcrypt
--  (PHP: password_hash / Node.js: bcrypt / Python: passlib).
--  Temporary password for all seeded users: FuelAudit@2026!
-- =============================================================

CREATE DATABASE IF NOT EXISTS fuel_variance_audit
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE fuel_variance_audit;

-- =============================================================
--  1. ROLES
-- =============================================================
CREATE TABLE roles (
  id          TINYINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name        VARCHAR(50)      NOT NULL,
  label       VARCHAR(100)     NOT NULL,
  created_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_roles_name (name)
) ENGINE=InnoDB;

INSERT INTO roles (name, label) VALUES
  ('admin',    'Administrator — Full Rights'),
  ('dispatch', 'Dispatch — Upload & View'),
  ('exco',     'Executive Committee — View & Download'),
  ('hod',      'Head of Department — View & Download');

-- =============================================================
--  2. ROLE PERMISSIONS
--  permission format:  resource.action
--    Resources : dashboard | analytics | records | drivers
--                documents | settings | tickets | users
--    Actions   : view | upload | edit | delete | create | manage
-- =============================================================
CREATE TABLE role_permissions (
  id          INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  role_id     TINYINT UNSIGNED NOT NULL,
  permission  VARCHAR(60)      NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_role_perm (role_id, permission),
  CONSTRAINT fk_rp_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Admin: every permission
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
JOIN (
  SELECT 'dashboard.view'   AS permission UNION ALL
  SELECT 'analytics.view'                 UNION ALL
  SELECT 'records.view'                   UNION ALL
  SELECT 'records.upload'                 UNION ALL
  SELECT 'records.edit'                   UNION ALL
  SELECT 'records.delete'                 UNION ALL
  SELECT 'drivers.view'                   UNION ALL
  SELECT 'drivers.edit'                   UNION ALL
  SELECT 'documents.view'                 UNION ALL
  SELECT 'documents.upload'               UNION ALL
  SELECT 'settings.view'                  UNION ALL
  SELECT 'settings.edit'                  UNION ALL
  SELECT 'tickets.view'                   UNION ALL
  SELECT 'records.download'               UNION ALL
  SELECT 'tickets.create'                 UNION ALL
  SELECT 'users.manage'
) p
WHERE r.name = 'admin';

-- Dispatch: view + upload only; no settings, no documents, no user management
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
JOIN (
  SELECT 'dashboard.view'  AS permission UNION ALL
  SELECT 'analytics.view'               UNION ALL
  SELECT 'records.view'                 UNION ALL
  SELECT 'records.upload'               UNION ALL
  SELECT 'drivers.view'                 UNION ALL
  SELECT 'tickets.view'                 UNION ALL
  SELECT 'tickets.create'
) p
WHERE r.name = 'dispatch';

-- Exco and HOD: view and download summary report; no upload, no settings, no user management
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
JOIN (
  SELECT 'dashboard.view'   AS permission UNION ALL
  SELECT 'analytics.view'               UNION ALL
  SELECT 'records.view'                 UNION ALL
  SELECT 'records.download'
) p
WHERE r.name IN ('exco', 'hod');

-- Exco and HOD: view and download summary report; no upload, no settings, no user management
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM roles r
JOIN (
  SELECT 'dashboard.view'   AS permission UNION ALL
  SELECT 'analytics.view'               UNION ALL
  SELECT 'records.view'                 UNION ALL
  SELECT 'records.download'
) p
WHERE r.name IN ('exco', 'hod');

-- =============================================================
--  3. USERS
-- =============================================================
CREATE TABLE users (
  id              INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  role_id         TINYINT UNSIGNED NOT NULL,
  full_name       VARCHAR(150)     NOT NULL,
  username        VARCHAR(60)      NOT NULL,
  email           VARCHAR(191)     NOT NULL,
  -- SHA2-256 placeholder; replace with bcrypt in production
  password_hash   CHAR(64)         NOT NULL,
  avatar_initials CHAR(3)          NULL,
  is_active       TINYINT(1)       NOT NULL DEFAULT 1,
  last_login_at   DATETIME         NULL,
  created_at      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_email    (email),
  CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB;

-- Temporary password: FuelAudit@2026!
--   SHA2('FuelAudit@2026!', 256)
INSERT INTO users (role_id, full_name, username, email, password_hash, avatar_initials) VALUES
  (
    (SELECT id FROM roles WHERE name = 'admin'),
    'Aobakwe Olatotse',
    'a.olatotse',
    'aaolatotse1@gmail.com',
    SHA2('FuelAudit@2026!', 256),
    'AO'
  ),
  (
    (SELECT id FROM roles WHERE name = 'admin'),
    'Prince Gaotlhobogwe',
    'p.gaotlhobogwe',
    'prince.gaotlhobogwe@skybridgelogistics.co.bw',
    SHA2('FuelAudit@2026!', 256),
    'PG'
  ),
  (
    (SELECT id FROM roles WHERE name = 'dispatch'),
    'Goitse Mogorosi',
    'g.mogorosi',
    'goitse.mogorosi@skybridgelogistics.co.bw',
    SHA2('FuelAudit@2026!', 256),
    'GM'
  );

-- =============================================================
--  4. OTP SESSIONS  (email one-time passwords)
-- =============================================================
CREATE TABLE otp_sessions (
  id          BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
  user_id     INT UNSIGNED     NOT NULL,
  otp_code    CHAR(6)          NOT NULL,
  expires_at  DATETIME         NOT NULL,
  used        TINYINT(1)       NOT NULL DEFAULT 0,
  created_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_otp_user (user_id),
  KEY idx_otp_expires (expires_at),
  CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- =============================================================
--  5. CONTRACTS  (lookup)
-- =============================================================
CREATE TABLE contracts (
  id    TINYINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name  VARCHAR(60)      NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_contracts_name (name)
) ENGINE=InnoDB;

INSERT INTO contracts (name) VALUES
  ('NATREF'), ('SECUNDA'), ('TARLTON'), ('WALVIS BAY'),
  ('MATOLA'), ('FRANCISTOWN'), ('ENERGY'), ('OTHER');

-- =============================================================
--  6. FUEL RECORDS  (main variance table)
-- =============================================================
CREATE TABLE fuel_records (
  id                   VARCHAR(36)      NOT NULL,          -- UUID from the app
  record_date          DATE             NOT NULL,
  vehicle              VARCHAR(60)      NOT NULL,
  driver               VARCHAR(120)     NOT NULL,
  loading_depot        VARCHAR(120)     NOT NULL,
  offloading_depot     VARCHAR(120)     NOT NULL,
  contract_id          TINYINT UNSIGNED NULL,
  contract_name        VARCHAR(60)      NOT NULL,          -- denormalised for historical accuracy
  product              VARCHAR(60)      NOT NULL,
  load_volume          DECIMAL(12,4)    NOT NULL,
  offload_volume       DECIMAL(12,4)    NOT NULL,
  variance             DECIMAL(12,4)    GENERATED ALWAYS AS (load_volume - offload_volume) STORED,
  variance_pct         DECIMAL(8,4)     GENERATED ALWAYS AS (
                         CASE WHEN load_volume = 0 THEN NULL
                              ELSE ((load_volume - offload_volume) / load_volume) * 100
                         END
                       ) STORED,
  order_no             VARCHAR(60)      NULL,
  imported_by          INT UNSIGNED     NULL,              -- users.id
  created_at           DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at           DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_fr_date        (record_date),
  KEY idx_fr_vehicle     (vehicle),
  KEY idx_fr_contract    (contract_id),
  KEY idx_fr_imported_by (imported_by),
  CONSTRAINT fk_fr_contract    FOREIGN KEY (contract_id)  REFERENCES contracts(id) ON DELETE SET NULL,
  CONSTRAINT fk_fr_imported_by FOREIGN KEY (imported_by)  REFERENCES users(id)     ON DELETE SET NULL
) ENGINE=InnoDB;

-- =============================================================
--  7. IMPORTS  (file import history)
-- =============================================================
CREATE TABLE imports (
  id            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  imported_by   INT UNSIGNED     NOT NULL,
  file_name     VARCHAR(255)     NOT NULL,
  file_size     INT UNSIGNED     NULL,
  record_count  INT UNSIGNED     NOT NULL DEFAULT 0,
  status        ENUM('pending','success','partial','failed') NOT NULL DEFAULT 'pending',
  error_detail  TEXT             NULL,
  imported_at   DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_imports_user (imported_by),
  CONSTRAINT fk_imports_user FOREIGN KEY (imported_by) REFERENCES users(id)
) ENGINE=InnoDB;

-- =============================================================
--  8. ATTACHMENTS  (per fuel record)
-- =============================================================
CREATE TABLE attachments (
  id          INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  record_id   VARCHAR(36)      NOT NULL,
  file_name   VARCHAR(255)     NOT NULL,
  file_type   VARCHAR(100)     NULL,
  file_size   INT UNSIGNED     NULL,
  storage_url VARCHAR(2048)    NULL,                       -- S3 / local path / base64 ref
  uploaded_by INT UNSIGNED     NULL,
  uploaded_at DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_att_record (record_id),
  CONSTRAINT fk_att_record      FOREIGN KEY (record_id)   REFERENCES fuel_records(id) ON DELETE CASCADE,
  CONSTRAINT fk_att_uploaded_by FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- =============================================================
--  9. SETTINGS  (key-value store for app-wide config)
-- =============================================================
CREATE TABLE settings (
  id          INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  setting_key VARCHAR(80)      NOT NULL,
  value       TEXT             NOT NULL,
  label       VARCHAR(150)     NULL,
  updated_by  INT UNSIGNED     NULL,
  updated_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_settings_key (setting_key),
  CONSTRAINT fk_settings_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Default tolerances (matches the app: unleaded 0.15%, diesel 0.25%)
INSERT INTO settings (setting_key, value, label) VALUES
  ('tolerance_unleaded',  '0.15',               'Unleaded variance tolerance (%)'),
  ('tolerance_diesel',    '0.25',               'Diesel variance tolerance (%)'),
  ('company_name',        'Sky Bridge Logistics','Company display name'),
  ('company_email',       'aaolatotse1@gmail.com', 'Company contact email'),
  ('otp_expiry_minutes',  '10',                 'OTP validity window (minutes)'),
  ('max_otp_attempts',    '3',                  'Max OTP attempts before lockout');

-- =============================================================
--  10. ZOHO CONFIG
-- =============================================================
CREATE TABLE zoho_config (
  id                      INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  domain                  VARCHAR(120)     NOT NULL DEFAULT '',
  org_id                  VARCHAR(60)      NOT NULL DEFAULT '',
  access_token            TEXT             NULL,
  department_id           VARCHAR(60)      NULL,
  default_assignee_id     VARCHAR(60)      NULL,
  contact_id              VARCHAR(60)      NULL,
  priority                VARCHAR(30)      NOT NULL DEFAULT 'Medium',
  include_custom_fields   TINYINT(1)       NOT NULL DEFAULT 0,
  auto_create_on_import   TINYINT(1)       NOT NULL DEFAULT 0,
  -- JSON object: { "NATREF": "assigneeId", ... }
  contract_assignees      JSON             NULL,
  flow_webhook_url        VARCHAR(2048)    NULL,
  zoho_form_url           VARCHAR(2048)    NULL,
  updated_by              INT UNSIGNED     NULL,
  updated_at              DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_zoho_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Single config row (app uses one Zoho workspace)
INSERT INTO zoho_config (domain, org_id, priority, include_custom_fields, auto_create_on_import)
VALUES ('https://desk.zoho.com', '', 'Medium', 0, 0);

-- =============================================================
--  11. ZOHO TICKETS  (tickets created from variance records)
-- =============================================================
CREATE TABLE zoho_tickets (
  id              INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  record_id       VARCHAR(36)      NOT NULL,
  zoho_ticket_id  VARCHAR(60)      NOT NULL,
  ticket_number   VARCHAR(30)      NULL,
  subject         VARCHAR(255)     NULL,
  status          VARCHAR(60)      NULL,
  created_by      INT UNSIGNED     NULL,
  created_at      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_zt_record (record_id),
  CONSTRAINT fk_zt_record     FOREIGN KEY (record_id)  REFERENCES fuel_records(id) ON DELETE CASCADE,
  CONSTRAINT fk_zt_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- =============================================================
--  12. AUDIT LOG  (immutable trail of all data changes)
-- =============================================================
CREATE TABLE audit_log (
  id          BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
  user_id     INT UNSIGNED     NULL,
  action      VARCHAR(80)      NOT NULL,
  entity      VARCHAR(60)      NOT NULL,
  entity_id   VARCHAR(36)      NULL,
  before_val  JSON             NULL,
  after_val   JSON             NULL,
  ip_address  VARCHAR(45)      NULL,
  user_agent  VARCHAR(512)     NULL,
  logged_at   DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_al_user   (user_id),
  KEY idx_al_entity (entity, entity_id),
  KEY idx_al_logged (logged_at),
  CONSTRAINT fk_al_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- =============================================================
--  QUICK REFERENCE — SEEDED DATA
-- =============================================================
--
--  ROLES
--  +---------+----------------------------------------------------+
--  | admin   | All 15 permissions (full rights)                   |
--  | dispatch| 7 permissions — records.view/upload, dashboard,    |
--  |         | analytics, drivers.view, tickets.view/create ONLY  |
--  +---------+----------------------------------------------------+
--
--  USERS  (all start with password: FuelAudit@2026!)
--  +----------------------+----------+----------------------------+
--  | Full Name            | Role     | Username                   |
--  +----------------------+----------+----------------------------+
--  | Aobakwe Olatotse     | admin    | a.olatotse                 |
--  | Prince Gaotlhobogwe  | admin    | p.gaotlhobogwe             |
--  | Goitse Mogorosi      | dispatch | g.mogorosi                 |
--  +----------------------+----------+----------------------------+
--
--  Update emails before deploying:
--    UPDATE users SET email = 'real@email.com' WHERE username = 'p.gaotlhobogwe';
--    UPDATE users SET email = 'real@email.com' WHERE username = 'g.mogorosi';
--
--  Force password change on first login by adding a
--  `must_change_password TINYINT(1) DEFAULT 1` column when ready.
-- =============================================================
