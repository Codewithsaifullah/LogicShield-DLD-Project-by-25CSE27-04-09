
-- ==========================================
-- LOGICSHIELD DATABASE SCHEMA
-- Allowed departments: CSE and SE
-- ==========================================

-- 1. STUDENT REGISTRY
CREATE TABLE IF NOT EXISTS student_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_number TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL CHECK (
        department IN (
            'COMPUTER SYSTEMS ENGINEERING',
            'SOFTWARE ENGINEERING'
        )
    ),
    batch TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_approved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. USERS
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student'
        CHECK (role IN ('admin', 'teacher', 'student')),
    student_id INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
        REFERENCES student_registry(id)
);

-- 3. PROTECTED FILES
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_name TEXT NOT NULL,
    storage_key TEXT NOT NULL UNIQUE,
    sensitivity TEXT NOT NULL DEFAULT 'normal',
    owner_id INTEGER NOT NULL,
    category TEXT NOT NULL DEFAULT 'study_material',
    department TEXT NOT NULL DEFAULT 'ALL',
    subject TEXT DEFAULT '',
    term TEXT DEFAULT '',
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (owner_id)
        REFERENCES users(id)
);

-- 4. FILE PERMISSIONS
CREATE TABLE IF NOT EXISTS file_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    can_read INTEGER NOT NULL DEFAULT 0,
    can_download INTEGER NOT NULL DEFAULT 0,

    UNIQUE(file_id, user_id),

    FOREIGN KEY (file_id)
        REFERENCES files(id),

    FOREIGN KEY (user_id)
        REFERENCES users(id)
);

-- 5. ACCESS EVENTS
CREATE TABLE IF NOT EXISTS access_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    file_id INTEGER,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id),

    FOREIGN KEY (file_id)
        REFERENCES files(id)
);

-- 6. AUDIT LOGS
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    action TEXT NOT NULL,
    target TEXT,
    result TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (actor_id)
        REFERENCES users(id)
);

-- 7. SECURITY ALERTS
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
);

-- 8. INDEXES
CREATE INDEX IF NOT EXISTS idx_student_enrollment
ON student_registry(enrollment_number);

CREATE INDEX IF NOT EXISTS idx_student_department
ON student_registry(department);

CREATE INDEX IF NOT EXISTS idx_users_student
ON users(student_id);

CREATE INDEX IF NOT EXISTS idx_access_events_user
ON access_events(user_id);
