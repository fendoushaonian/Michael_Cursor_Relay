/**
 * KC-MCP Database Initialization
 * Tables reverse-engineered from console.html frontend
 */
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'kc.db');
const fs = require('fs');
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ═══ Core Tables ═══
db.exec(`
  -- Admin users & agents
  CREATE TABLE IF NOT EXISTS admin_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    role TEXT DEFAULT 'agent',  -- 'super' or 'agent'
    permissions TEXT DEFAULT '[]',  -- JSON array
    note TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- License keys
  CREATE TABLE IF NOT EXISTS license_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'active',   -- active, disabled, expired
    key_type TEXT DEFAULT 'basic',  -- basic, pro, enterprise
    tier TEXT DEFAULT 'basic',
    device_id TEXT DEFAULT '',
    device_hash TEXT DEFAULT '',
    activated_at DATETIME,
    expires_at DATETIME,
    group_id INTEGER DEFAULT NULL,
    note TEXT DEFAULT '',
    no_quota INTEGER DEFAULT 0,
    permissions TEXT DEFAULT '[]',
    max_devices INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- License groups
  CREATE TABLE IF NOT EXISTS license_group (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Cursor accounts pool
  CREATE TABLE IF NOT EXISTS cursor_account (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    token TEXT DEFAULT '',
    workos_token TEXT DEFAULT '',
    status TEXT DEFAULT 'active',  -- active, expired, disabled, error
    usage_quota REAL DEFAULT 0,
    usage_used REAL DEFAULT 0,
    billing_cycle_start DATETIME,
    billing_cycle_end DATETIME,
    model_usage TEXT DEFAULT '{}',
    assigned_license_id INTEGER DEFAULT NULL,
    note TEXT DEFAULT '',
    last_sync_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Device blacklist
  CREATE TABLE IF NOT EXISTS device_blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_hash TEXT NOT NULL,
    reason TEXT DEFAULT '',
    status TEXT DEFAULT 'active',   -- active, inactive
    banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    unbanned_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- IP blacklist
  CREATE TABLE IF NOT EXISTS ip_blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Security events
  CREATE TABLE IF NOT EXISTS security_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    device_hash TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    version TEXT DEFAULT '',
    details TEXT DEFAULT '{}',
    severity TEXT DEFAULT 'medium',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Bundle tamper log
  CREATE TABLE IF NOT EXISTS bundle_tamper_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_hash TEXT DEFAULT '',
    license_key TEXT DEFAULT '',
    bundle_hash TEXT DEFAULT '',
    expected_hash TEXT DEFAULT '',
    action TEXT DEFAULT 'tamper',
    version TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Version management
  CREATE TABLE IF NOT EXISTS version (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    build_id TEXT DEFAULT '',
    platform TEXT DEFAULT 'all',
    channel TEXT DEFAULT 'stable',
    download_url TEXT DEFAULT '',
    changelog TEXT DEFAULT '',
    min_version TEXT DEFAULT '',
    status TEXT DEFAULT 'draft',  -- draft, published, disabled
    force_update INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    published_at DATETIME
  );

  -- Enc key shares (the critical table)
  CREATE TABLE IF NOT EXISTS enc_key_share (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    build_id TEXT NOT NULL,
    bundle_hash TEXT DEFAULT '',
    share TEXT NOT NULL,
    source TEXT DEFAULT 'upstream',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(build_id, bundle_hash)
  );

  -- Update/download logs
  CREATE TABLE IF NOT EXISTS update_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_hash TEXT DEFAULT '',
    license_key TEXT DEFAULT '',
    version TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    action TEXT DEFAULT 'download',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- License verify log
  CREATE TABLE IF NOT EXISTS license_verify_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT DEFAULT '',
    device_id TEXT DEFAULT '',
    device_hash TEXT DEFAULT '',
    action TEXT DEFAULT 'verify',  -- activate, verify, unbind
    ip TEXT DEFAULT '',
    version TEXT DEFAULT '',
    success INTEGER DEFAULT 1,
    message TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Operation logs (admin audit trail)
  CREATE TABLE IF NOT EXISTS operation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT DEFAULT '',
    actor TEXT DEFAULT '',
    module TEXT DEFAULT '',
    action TEXT NOT NULL,
    target TEXT DEFAULT '',
    details TEXT DEFAULT '{}',
    ip TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Admin login logs
  CREATE TABLE IF NOT EXISTS admin_login_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    success INTEGER DEFAULT 0,
    message TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Announcements
  CREATE TABLE IF NOT EXISTS announcement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT DEFAULT '',
    type TEXT DEFAULT 'info',
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Device poison scripts
  CREATE TABLE IF NOT EXISTS device_poison (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_hash TEXT NOT NULL,
    script_type TEXT DEFAULT 'stub',
    reason TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- PKCE tokens
  CREATE TABLE IF NOT EXISTS pkce_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_verifier TEXT DEFAULT '',
    code_challenge TEXT DEFAULT '',
    state TEXT DEFAULT '',
    token TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Settings (key-value)
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT '{}'
  );

  -- Report logs
  CREATE TABLE IF NOT EXISTS report_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT DEFAULT '',
    email TEXT DEFAULT '',
    device_hash TEXT DEFAULT '',
    content TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Cloud service instances
  CREATE TABLE IF NOT EXISTS cloud_instance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT DEFAULT '',
    server_ip TEXT NOT NULL,
    proxy_port INTEGER DEFAULT 8901,
    status TEXT DEFAULT 'offline',  -- online, offline, error
    region TEXT DEFAULT '',
    max_sessions INTEGER DEFAULT 50,
    active_sessions INTEGER DEFAULT 0,
    last_heartbeat DATETIME,
    cpu_usage REAL DEFAULT 0,
    memory_usage REAL DEFAULT 0,
    note TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Cloud active sessions (who is using which instance)
  CREATE TABLE IF NOT EXISTS cloud_session (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id INTEGER DEFAULT NULL,
    license_key TEXT DEFAULT '',
    device_hash TEXT DEFAULT '',
    client_ip TEXT DEFAULT '',
    account_email TEXT DEFAULT '',
    status TEXT DEFAULT 'active',  -- active, idle, disconnected
    requests_count INTEGER DEFAULT 0,
    last_request_at DATETIME,
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    disconnected_at DATETIME,
    FOREIGN KEY (instance_id) REFERENCES cloud_instance(id)
  );

  -- Cloud proxy logs
  CREATE TABLE IF NOT EXISTS cloud_proxy_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id INTEGER DEFAULT NULL,
    license_key TEXT DEFAULT '',
    client_ip TEXT DEFAULT '',
    account_email TEXT DEFAULT '',
    request_path TEXT DEFAULT '',
    status_code INTEGER DEFAULT 0,
    response_time_ms INTEGER DEFAULT 0,
    success INTEGER DEFAULT 1,
    error_message TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Nonce replay prevention
  CREATE TABLE IF NOT EXISTS used_nonce (
    nonce TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ═══ Create default admin user ═══
const hash = bcrypt.hashSync('2007032255rty', 10);
const stmt = db.prepare(`INSERT OR IGNORE INTO admin_user (username, password_hash, role, display_name) VALUES (?, ?, 'super', '超级管理员')`);
stmt.run('admin', hash);

// ═══ Default settings ═══
const defaultSettings = {
  smtp: JSON.stringify({ enabled: false, host: 'smtp.qq.com', port: 465, secure: true, user: '', pass: '', notifyTo: '' }),
  tasks: JSON.stringify({ enabled: false }),
  'free-trial': JSON.stringify({ enabled: false, expiresAt: '', message: '' }),
  carousel: JSON.stringify({ mode: 'random', messages: [] }),
  'patch-recipe': JSON.stringify({ enabled: true }),
  installer: JSON.stringify({ enabled: true })
};

const settingsStmt = db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`);
for (const [k, v] of Object.entries(defaultSettings)) {
  settingsStmt.run(k, v);
}

// ═══ Migration: add missing columns to existing tables ═══
const migrations = [
  { table: 'bundle_tamper_log', column: 'action', def: "TEXT DEFAULT 'tamper'" },
  { table: 'bundle_tamper_log', column: 'version', def: "TEXT DEFAULT ''" },
  { table: 'operation_log', column: 'actor', def: "TEXT DEFAULT ''" },
  { table: 'operation_log', column: 'module', def: "TEXT DEFAULT ''" },
  { table: 'report_log', column: 'email', def: "TEXT DEFAULT ''" },
  { table: 'security_event', column: 'version', def: "TEXT DEFAULT ''" },
  { table: 'version', column: 'download_count', def: "INTEGER DEFAULT 0" },
];

for (const m of migrations) {
  try {
    const cols = db.pragma(`table_info(${m.table})`).map(c => c.name);
    if (!cols.includes(m.column)) {
      db.exec(`ALTER TABLE ${m.table} ADD COLUMN ${m.column} ${m.def}`);
      console.log(`  ✅ Added ${m.table}.${m.column}`);
    }
  } catch (e) {
    console.log(`  ⚠️ Migration ${m.table}.${m.column}: ${e.message}`);
  }
}

console.log('✅ Database initialized at:', DB_PATH);
console.log('   Default admin: admin / 2007032255rty');
db.close();
