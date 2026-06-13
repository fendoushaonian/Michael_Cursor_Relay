/**
 * KC-MCP Server — Full admin backend (reverse-engineered from console.html)
 * Port: 8900 (admin panel + client API)
 */
const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 8900;
const JWT_SECRET = process.env.JWT_SECRET;
const SIGN_SECRET = process.env.SIGN_SECRET;

if (!JWT_SECRET || !SIGN_SECRET) {
  console.error('❌ [FATAL] 必须设置环境变量: JWT_SECRET, SIGN_SECRET');
  console.error('   示例: JWT_SECRET=$(openssl rand -hex 32) SIGN_SECRET=$(openssl rand -hex 32) node server.js');
  process.exit(1);
}

// ═══ Database ═══
const DB_PATH = path.join(__dirname, 'data', 'kc.db');
if (!fs.existsSync(DB_PATH)) {
  console.error('❌ Database not found. Run: node init-db.js');
  process.exit(1);
}
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ═══ Auto-migration: add missing columns ═══
const migrations = [
  { table: 'bundle_tamper_log', column: 'action', def: "TEXT DEFAULT 'tamper'" },
  { table: 'bundle_tamper_log', column: 'version', def: "TEXT DEFAULT ''" },
  { table: 'operation_log', column: 'actor', def: "TEXT DEFAULT ''" },
  { table: 'operation_log', column: 'module', def: "TEXT DEFAULT ''" },
  { table: 'report_log', column: 'email', def: "TEXT DEFAULT ''" },
  { table: 'security_event', column: 'version', def: "TEXT DEFAULT ''" },
  { table: 'version', column: 'download_count', def: "INTEGER DEFAULT 0" },
];

try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS cloud_instance (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT DEFAULT '', server_ip TEXT NOT NULL,
      proxy_port INTEGER DEFAULT 8901, status TEXT DEFAULT 'offline', region TEXT DEFAULT '',
      max_sessions INTEGER DEFAULT 50, active_sessions INTEGER DEFAULT 0,
      last_heartbeat DATETIME, cpu_usage REAL DEFAULT 0, memory_usage REAL DEFAULT 0,
      note TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS cloud_session (
      id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id INTEGER, license_key TEXT DEFAULT '',
      device_hash TEXT DEFAULT '', client_ip TEXT DEFAULT '', account_email TEXT DEFAULT '',
      status TEXT DEFAULT 'active', requests_count INTEGER DEFAULT 0,
      last_request_at DATETIME, connected_at DATETIME DEFAULT CURRENT_TIMESTAMP, disconnected_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS cloud_proxy_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id INTEGER, license_key TEXT DEFAULT '',
      client_ip TEXT DEFAULT '', account_email TEXT DEFAULT '', request_path TEXT DEFAULT '',
      status_code INTEGER DEFAULT 0, response_time_ms INTEGER DEFAULT 0, success INTEGER DEFAULT 1,
      error_message TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
} catch (e) {}
for (const m of migrations) {
  try {
    const cols = db.pragma(`table_info(${m.table})`).map(c => c.name);
    if (!cols.includes(m.column)) {
      db.exec(`ALTER TABLE ${m.table} ADD COLUMN ${m.column} ${m.def}`);
      console.log(`  ✅ Migrated: ${m.table}.${m.column}`);
    }
  } catch {}
}

// ═══ SMTP transporter (lazy init from settings) ═══
let smtpTransporter = null;
function getSmtpTransporter() {
  try {
    const row = db.prepare("SELECT value FROM settings WHERE key='smtp'").get();
    if (!row) return null;
    const cfg = JSON.parse(row.value);
    if (!cfg.enabled || !cfg.host || !cfg.user || !cfg.pass) return null;
    smtpTransporter = nodemailer.createTransport({
      host: cfg.host,
      port: cfg.port || 465,
      secure: cfg.secure !== false,
      auth: { user: cfg.user, pass: cfg.pass },
      tls: { rejectUnauthorized: false }
    });
    return smtpTransporter;
  } catch { return null; }
}

// ═══ Scheduled tasks ═══
const activeCronJobs = {};

function setupCronJobs() {
  for (const key of Object.keys(activeCronJobs)) {
    activeCronJobs[key].stop();
    delete activeCronJobs[key];
  }
  try {
    const row = db.prepare("SELECT value FROM settings WHERE key='tasks'").get();
    if (!row) return;
    const cfg = JSON.parse(row.value);
    if (!cfg.enabled) return;

    activeCronJobs['expire-check'] = cron.schedule('0 */6 * * *', () => {
      try {
        const expired = db.prepare("UPDATE license_key SET status='expired' WHERE status='active' AND expires_at IS NOT NULL AND expires_at < datetime('now')").run();
        if (expired.changes > 0) console.log(`[CRON] Expired ${expired.changes} license keys`);
        const expiredAccounts = db.prepare("UPDATE cursor_account SET status='expired' WHERE status='active' AND billing_cycle_end IS NOT NULL AND billing_cycle_end < datetime('now')").run();
        if (expiredAccounts.changes > 0) console.log(`[CRON] Expired ${expiredAccounts.changes} accounts`);
      } catch (e) { console.error('[CRON] expire-check error:', e.message); }
    });

    activeCronJobs['nonce-cleanup'] = cron.schedule('0 3 * * *', () => {
      try {
        const ts = Math.floor(Date.now() / 1000) - 86400;
        const r = db.prepare('DELETE FROM used_nonce WHERE ts < ?').run(ts);
        console.log(`[CRON] Cleaned ${r.changes} expired nonces`);
      } catch (e) { console.error('[CRON] nonce-cleanup error:', e.message); }
    });

    activeCronJobs['security-scan'] = cron.schedule('*/30 * * * *', () => {
      try {
        const suspicious = db.prepare("SELECT ip, COUNT(*) as cnt FROM license_verify_log WHERE success=0 AND created_at > datetime('now','-1 hour') GROUP BY ip HAVING cnt >= 10").all();
        for (const s of suspicious) {
          const exists = db.prepare("SELECT id FROM ip_blacklist WHERE ip=? AND status='active'").get(s.ip);
          if (!exists) {
            db.prepare("INSERT INTO ip_blacklist (ip, reason) VALUES (?, ?)").run(s.ip, `auto-ban: ${s.cnt} failed verifications in 1h`);
            console.log(`[CRON] Auto-banned IP: ${s.ip} (${s.cnt} failures)`);
          }
        }
      } catch (e) { console.error('[CRON] security-scan error:', e.message); }
    });

    console.log('✅ Cron jobs started: expire-check(6h), nonce-cleanup(daily), security-scan(30min)');
  } catch (e) { console.error('[CRON] Setup error:', e.message); }
}

setupCronJobs();

// ═══ michael-vip MySQL bridge ═══
// The REAL license/device data lives in the michael-vip license server's MySQL
// (port 443 service). The console reads it from here so the dashboard and the
// user (machine-code) management reflect production data instead of the local
// SQLite mirror. Degrades gracefully to SQLite when the bridge is unavailable.
let mvPool = null;
try {
  const mysql = require('mysql2/promise');
  mvPool = mysql.createPool({
    host: process.env.MV_DB_HOST || '127.0.0.1',
    user: process.env.MV_DB_USER || 'root',
    password: process.env.MV_DB_PASSWORD || 'Michael@2026',
    database: process.env.MV_DB_NAME || 'michael_vip',
    socketPath: process.env.MV_MYSQL_SOCKET || '/var/run/mysqld/mysqld.sock',
    waitForConnections: true,
    connectionLimit: 5,
    charset: 'utf8mb4'
  });
  console.log('✅ michael-vip MySQL bridge initialized');
} catch (e) {
  console.error('⚠️ mysql2 not available — real-data bridge disabled:', e.message);
}
async function mvQuery(sql, params = []) {
  if (!mvPool) throw new Error('mv-bridge-unavailable');
  const [rows] = await mvPool.query(sql, params);
  return rows;
}

// Normalize an IPv4-mapped IPv6 address (::ffff:1.2.3.4) to plain IPv4 for display.
function cleanIp(ip) { return (ip || '').replace(/^::ffff:/, ''); }
// Render an activation_logs JSON `details` blob into a short human-readable string.
function fmtDetails(d) {
  if (!d) return '';
  let o = d;
  if (typeof d === 'string') { try { o = JSON.parse(d); } catch { return d; } }
  if (o && typeof o === 'object') {
    if (o.reason) return o.reason + (o.current !== undefined ? ` (当前${o.current})` : '');
    const parts = Object.entries(o).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`);
    return parts.join(', ');
  }
  return String(o);
}

// ═══ Middleware ═══
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').filter(Boolean);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  },
  credentials: true
}));
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ═══ Rate limiting ═══
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { code: 429, message: '登录尝试过于频繁，请15分钟后重试' } });

// ═══ Auth middleware ═══
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ code: 401, message: '未登录' });
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ code: 401, message: 'Token 无效或已过期' });
  }
}

function permCheck(perm) {
  return (req, res, next) => {
    if (req.user.role === 'super') return next();
    const perms = req.user.permissions || [];
    if (perms.includes(perm)) return next();
    return res.status(403).json({ code: 403, message: '无权限执行此操作' });
  };
}

// ═══ Admin Routes ═══
const admin = express.Router();
admin.use(authMiddleware);

// 操作日志：自动记录所有后台写操作（增/删/改），无需逐个端点埋点。
function _redactOp(o) {
  if (!o || typeof o !== 'object') return {};
  const c = {};
  for (const k of Object.keys(o)) c[k] = /pass|token|secret/i.test(k) ? '***' : o[k];
  return c;
}
function logOp(req, mod, action, target, details) {
  try {
    const u = req.user || {};
    const name = u.username || u.display_name || (u.id ? ('uid:' + u.id) : 'admin');
    db.prepare('INSERT INTO operation_log (username, actor, module, action, target, details, ip) VALUES (?,?,?,?,?,?,?)')
      .run(name, name, mod || '', action || '', target || '', JSON.stringify(details || {}), req.ip || '');
  } catch (e) {}
}
admin.use((req, res, next) => {
  if (req.method === 'GET') return next();
  res.on('finish', () => {
    try {
      if (res.statusCode >= 200 && res.statusCode < 400) {
        const seg = (req.path || '').split('/').filter(Boolean);
        const mod = (seg[0] || 'admin').replace(/-/g, '_');
        const target = seg.slice(1).join('/') || (req.body && (req.body.id || req.body.license_key || req.body.version || req.body.title)) || '';
        logOp(req, mod, req.method + ' /' + seg.join('/'), String(target), _redactOp(req.body));
      }
    } catch (e) {}
  });
  next();
});

// --- Me ---
admin.get('/me', (req, res) => {
  const user = db.prepare('SELECT id, username, display_name, role, permissions, status FROM admin_user WHERE id = ?').get(req.user.id);
  res.json({ code: 0, data: user ? { ...user, permissions: JSON.parse(user.permissions || '[]') } : null });
});

admin.post('/me/password', (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM admin_user WHERE id = ?').get(req.user.id);
  if (!user || !bcrypt.compareSync(oldPassword, user.password_hash)) return res.json({ code: 400, message: '原密码错误' });
  db.prepare('UPDATE admin_user SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), req.user.id);
  res.json({ code: 0, message: '密码已修改' });
});

// --- Stats ---
// Licenses + users (active machine codes) come from michael-vip's real MySQL;
// versions/downloads stay in this console's own SQLite. "用户" = a machine code
// that is actively bound (one running device = one user).
admin.get('/stats', async (req, res) => {
  let totalVersions = 0, totalDownloads = 0;
  try {
    const [{ c }] = await mvQuery('SELECT COUNT(*) AS c FROM app_versions');
    const [{ d }] = await mvQuery('SELECT COALESCE(SUM(download_count),0) AS d FROM app_versions');
    totalVersions = c; totalDownloads = d;
  } catch {}
  try {
    const lic = await mvQuery('SELECT status, COUNT(*) AS c FROM license_keys GROUP BY status');
    let totalLicenses = 0, activeLicenses = 0, unusedLicenses = 0;
    for (const r of lic) {
      totalLicenses += r.c;
      if (r.status === 'active') activeLicenses = r.c;
      else if (r.status === 'unused') unusedLicenses = r.c;
    }
    const [{ c: totalAccounts }] = await mvQuery('SELECT COUNT(*) AS c FROM device_bindings WHERE is_active = 1');
    const [{ c: activeAccounts }] = await mvQuery("SELECT COUNT(*) AS c FROM device_bindings WHERE is_active = 1 AND last_heartbeat > DATE_SUB(NOW(), INTERVAL 7 DAY)");
    const expiredAccounts = Math.max(0, totalAccounts - activeAccounts);
    return res.json({ code: 0, data: { totalLicenses, activeLicenses, unusedLicenses, totalAccounts, activeAccounts, expiredAccounts, totalVersions, totalDownloads, source: 'michael-vip' } });
  } catch (e) {
    const totalLicenses = db.prepare('SELECT COUNT(*) as c FROM license_key').get().c;
    const activeLicenses = db.prepare("SELECT COUNT(*) as c FROM license_key WHERE status = 'active'").get().c;
    const unusedLicenses = db.prepare("SELECT COUNT(*) as c FROM license_key WHERE status = 'unused' OR (status = 'active' AND device_id IS NULL)").get().c;
    const totalAccounts = db.prepare('SELECT COUNT(*) as c FROM cursor_account').get().c;
    const activeAccounts = db.prepare("SELECT COUNT(*) as c FROM cursor_account WHERE status = 'active'").get().c;
    const expiredAccounts = db.prepare("SELECT COUNT(*) as c FROM cursor_account WHERE status = 'expired'").get().c;
    return res.json({ code: 0, data: { totalLicenses, activeLicenses, unusedLicenses, totalAccounts, activeAccounts, expiredAccounts, totalVersions, totalDownloads, source: 'sqlite-fallback' } });
  }
});

admin.get('/security-stats', (req, res) => {
  const ipTotal = db.prepare('SELECT COUNT(*) as c FROM ip_blacklist').get().c;
  const ipActive = db.prepare("SELECT COUNT(*) as c FROM ip_blacklist WHERE status='active'").get().c;
  let ipAuto24h = 0;
  try { ipAuto24h = db.prepare("SELECT COUNT(*) as c FROM ip_blacklist WHERE reason LIKE '%auto%' AND created_at > datetime('now','-1 day')").get().c; } catch {}

  const devTotal = db.prepare('SELECT COUNT(*) as c FROM device_blacklist').get().c;
  const devActive = db.prepare("SELECT COUNT(*) as c FROM device_blacklist WHERE status='active'").get().c;

  let adminFails = 0, adminUniqueIps = 0, adminTopIps = [];
  try {
    adminFails = db.prepare("SELECT COUNT(*) as c FROM admin_login_log WHERE success=0 AND created_at > datetime('now','-1 day')").get().c;
    adminTopIps = db.prepare("SELECT ip, COUNT(*) as cnt FROM admin_login_log WHERE success=0 AND created_at > datetime('now','-1 day') GROUP BY ip ORDER BY cnt DESC LIMIT 5").all();
    adminUniqueIps = adminTopIps.length;
  } catch {}

  let licFailTotal = 0, licByReason = {};
  try {
    licFailTotal = db.prepare("SELECT COUNT(*) as c FROM license_verify_log WHERE success=0 AND created_at > datetime('now','-1 day')").get().c;
    const reasons = db.prepare("SELECT message, COUNT(*) as cnt FROM license_verify_log WHERE success=0 AND created_at > datetime('now','-1 day') GROUP BY message").all();
    for (const r of reasons) licByReason[r.message || 'unknown'] = r.cnt;
  } catch {}

  let secHighRisk = 0, secByType = {};
  try {
    secHighRisk = db.prepare("SELECT COUNT(*) as c FROM security_event WHERE created_at > datetime('now','-1 day')").get().c;
    const types = db.prepare("SELECT event_type, COUNT(*) as cnt FROM security_event WHERE created_at > datetime('now','-1 day') GROUP BY event_type").all();
    for (const t of types) secByType[t.event_type] = t.cnt;
  } catch {}

  const recentAutoBan = db.prepare("SELECT * FROM device_blacklist WHERE reason LIKE '%auto%' ORDER BY created_at DESC LIMIT 5").all();

  res.json({ code: 0, data: {
    ipBlacklist: { total: ipTotal, active: ipActive, autoLast24h: ipAuto24h },
    deviceBlacklist: { total: devTotal, active: devActive },
    adminBruteForce24h: { fails: adminFails, uniqueIps: adminUniqueIps, topIps: adminTopIps },
    licenseFail24h: { total: licFailTotal, byReason: licByReason },
    securityEvent24h: { highRiskTotal: secHighRisk, byType: secByType, crossIpDevices: [] },
    recentAutoBan,
  }});
});

// --- Licenses (backed by michael-vip MySQL — the real card database) ---
// key_type is ENUM('trial','daily','monthly','yearly','lifetime'); map the
// console's richer type set onto it while keeping the true duration in days.
const LIC_TYPE_MAP = {
  hour: { kt: 'trial', days: 1, prefix: 'TRIAL' },
  trial: { kt: 'trial', days: 7, prefix: 'TRIAL' },
  day: { kt: 'daily', days: 1, prefix: 'DAY' },
  daily: { kt: 'daily', days: 1, prefix: 'DAY' },
  week: { kt: 'daily', days: 7, prefix: 'WEEK' },
  month: { kt: 'monthly', days: 30, prefix: 'MONTH' },
  monthly: { kt: 'monthly', days: 30, prefix: 'MONTH' },
  season: { kt: 'monthly', days: 90, prefix: 'SEASON' },
  year: { kt: 'yearly', days: 365, prefix: 'YEAR' },
  yearly: { kt: 'yearly', days: 365, prefix: 'YEAR' },
  permanent: { kt: 'lifetime', days: 99999, prefix: 'LIFE' },
  lifetime: { kt: 'lifetime', days: 99999, prefix: 'LIFE' }
};
function mapLicType(t) { return LIC_TYPE_MAP[t] || LIC_TYPE_MAP.monthly; }
function genLicKey(prefix) {
  const rand = crypto.randomBytes(8).toString('hex').toUpperCase();
  return `MVIP-${prefix}-${rand.slice(0, 4)}-${rand.slice(4, 8)}`;
}

admin.get('/licenses', async (req, res) => {
  const { page = 1, pageSize = 10, status, search, key_type } = req.query;
  try {
    let where = '1=1';
    const params = [];
    if (status) { where += ' AND k.status = ?'; params.push(status); }
    if (key_type) { where += ' AND k.key_type = ?'; params.push(key_type); }
    if (search) {
      where += ' AND (k.license_key LIKE ? OR k.id IN (SELECT license_id FROM device_bindings WHERE machine_id LIKE ? OR machine_name LIKE ?))';
      const s = `%${search}%`; params.push(s, s, s);
    }
    const [{ c: total }] = await mvQuery(`SELECT COUNT(*) AS c FROM license_keys k WHERE ${where}`, params);
    const offset = (Math.max(1, +page) - 1) * (+pageSize);
    const rows = await mvQuery(`
      SELECT k.id, k.license_key, k.key_type, k.status, k.max_devices, k.duration_days, k.created_at,
        (SELECT b.machine_id   FROM device_bindings b WHERE b.license_id=k.id AND b.is_active=1 ORDER BY b.last_heartbeat DESC LIMIT 1) AS device_id,
        (SELECT b.machine_name FROM device_bindings b WHERE b.license_id=k.id AND b.is_active=1 ORDER BY b.last_heartbeat DESC LIMIT 1) AS device_name,
        (SELECT b.activated_at FROM device_bindings b WHERE b.license_id=k.id AND b.is_active=1 ORDER BY b.last_heartbeat DESC LIMIT 1) AS activated_at,
        (SELECT b.expires_at   FROM device_bindings b WHERE b.license_id=k.id AND b.is_active=1 ORDER BY b.last_heartbeat DESC LIMIT 1) AS expires_at,
        (SELECT b.last_heartbeat FROM device_bindings b WHERE b.license_id=k.id AND b.is_active=1 ORDER BY b.last_heartbeat DESC LIMIT 1) AS last_active_at,
        (SELECT COUNT(*) FROM device_bindings b WHERE b.license_id=k.id AND b.is_active=1) AS active_devices,
        (SELECT l.ip_address FROM activation_logs l WHERE l.license_id=k.id ORDER BY l.created_at DESC LIMIT 1) AS last_ip
      FROM license_keys k WHERE ${where} ORDER BY k.id DESC LIMIT ? OFFSET ?`, [...params, +pageSize, offset]);
    const list = rows.map(r => ({
      id: r.id,
      license_key: r.license_key,
      key_type: r.key_type,
      status: r.status,
      max_devices: r.max_devices,
      duration_days: r.duration_days,
      created_at: r.created_at,
      device_id: r.device_id || '',
      device_name: r.device_name || '',
      device_count: r.active_devices,
      last_ip: r.last_ip || '',
      activated_at: r.activated_at,
      expires_at: r.expires_at,
      last_active_at: r.last_active_at,
      // fields the console renders but michael-vip does not model → safe defaults
      note: '', permissions: [], group_name: null, group_color: null,
      qq_number: null, unbind_count: 0, device_hash16: '', download_count_24h: 0
    }));
    res.json({ code: 0, data: { list, total, page: +page, pageSize: +pageSize, source: 'michael-vip' } });
  } catch (e) {
    res.json({ code: 0, data: { list: [], total: 0, page: +page, pageSize: +pageSize, error: e.message } });
  }
});

admin.get('/licenses/stats', async (req, res) => {
  try {
    const rows = await mvQuery('SELECT status, COUNT(*) AS c FROM license_keys GROUP BY status');
    let total = 0, active = 0, expired = 0, disabled = 0, unused = 0;
    for (const r of rows) {
      total += r.c;
      if (r.status === 'active') active = r.c;
      else if (r.status === 'expired') expired = r.c;
      else if (r.status === 'disabled') disabled = r.c;
      else if (r.status === 'unused') unused = r.c;
    }
    res.json({ code: 0, data: { total, active, expired, disabled, unused } });
  } catch (e) {
    res.json({ code: 0, data: { total: 0, active: 0, expired: 0, disabled: 0, unused: 0, error: e.message } });
  }
});

admin.post('/licenses', async (req, res) => {
  const { key_type, max_devices } = req.body;
  try {
    const m = mapLicType(key_type);
    const key = genLicKey(m.prefix);
    await mvQuery('INSERT INTO license_keys (license_key, key_type, max_devices, duration_days) VALUES (?,?,?,?)',
      [key, m.kt, parseInt(max_devices) || 1, m.days]);
    res.json({ code: 0, message: '创建成功', data: { license_key: key } });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

admin.post('/licenses/batch', async (req, res) => {
  const { count = 1, key_type, max_devices } = req.body;
  try {
    const m = mapLicType(key_type);
    const keys = [];
    const n = Math.min(parseInt(count) || 1, 1000);
    for (let i = 0; i < n; i++) {
      const key = genLicKey(m.prefix);
      await mvQuery('INSERT INTO license_keys (license_key, key_type, max_devices, duration_days) VALUES (?,?,?,?)',
        [key, m.kt, parseInt(max_devices) || 1, m.days]);
      keys.push(key);
    }
    res.json({ code: 0, data: keys, message: `已生成 ${keys.length} 个卡密` });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

admin.patch('/licenses/:id', async (req, res) => {
  const { status, key_type, max_devices } = req.body;
  try {
    const sets = []; const params = [];
    if (status !== undefined) { sets.push('status = ?'); params.push(status); }
    if (key_type !== undefined) { sets.push('key_type = ?'); params.push(mapLicType(key_type).kt); }
    if (max_devices !== undefined) { sets.push('max_devices = ?'); params.push(parseInt(max_devices) || 1); }
    if (!sets.length) return res.json({ code: 400, message: '无可更新字段' });
    params.push(req.params.id);
    await mvQuery(`UPDATE license_keys SET ${sets.join(', ')} WHERE id = ?`, params);
    if (status === 'disabled') await mvQuery('UPDATE device_bindings SET is_active = 0 WHERE license_id = ?', [req.params.id]);
    res.json({ code: 0, message: '已更新' });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

admin.delete('/licenses/:id', async (req, res) => {
  try {
    await mvQuery('DELETE FROM device_bindings WHERE license_id = ?', [req.params.id]);
    await mvQuery('DELETE FROM license_keys WHERE id = ?', [req.params.id]);
    res.json({ code: 0, message: '已删除' });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

admin.post('/licenses/:id/full-reset', async (req, res) => {
  try {
    const [r] = await mvQuery('UPDATE device_bindings SET is_active = 0 WHERE license_id = ?', [req.params.id]);
    await mvQuery("UPDATE license_keys SET status = 'unused' WHERE id = ?", [req.params.id]);
    res.json({ code: 0, message: '已重置（解绑全部设备）', data: { unbound: (r && r.affectedRows) || 0 } });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

admin.post('/licenses/toggle', async (req, res) => {
  const { ids, status } = req.body;
  if (!ids || !Array.isArray(ids) || !ids.length) return res.json({ code: 400, message: '缺少ids' });
  try {
    const placeholders = ids.map(() => '?').join(',');
    await mvQuery(`UPDATE license_keys SET status = ? WHERE id IN (${placeholders})`, [status, ...ids]);
    if (status === 'disabled') await mvQuery(`UPDATE device_bindings SET is_active = 0 WHERE license_id IN (${placeholders})`, ids);
    res.json({ code: 0, message: `已切换 ${ids.length} 个` });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

admin.post('/licenses/batch-delete', async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids) || !ids.length) return res.json({ code: 400, message: '缺少ids' });
  try {
    const placeholders = ids.map(() => '?').join(',');
    await mvQuery(`DELETE FROM device_bindings WHERE license_id IN (${placeholders})`, ids);
    await mvQuery(`DELETE FROM license_keys WHERE id IN (${placeholders})`, ids);
    res.json({ code: 0, message: `已删除 ${ids.length} 个` });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

// --- License Groups ---
admin.get('/license-groups', (req, res) => {
  let list;
  try {
    list = db.prepare("SELECT g.*, COALESCE(c.cnt,0) as license_count, COALESCE(c.act,0) as active_count FROM license_group g LEFT JOIN (SELECT group_id, COUNT(*) as cnt, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as act FROM license_key GROUP BY group_id) c ON g.id = c.group_id ORDER BY g.id DESC").all();
  } catch { list = db.prepare('SELECT * FROM license_group ORDER BY id DESC').all(); }
  let ungrouped_count = 0;
  try { ungrouped_count = db.prepare("SELECT COUNT(*) as c FROM license_key WHERE group_id IS NULL OR group_id = ''").get().c; } catch {}
  res.json({ code: 0, data: { list, ungrouped_count } });
});
admin.post('/license-groups', (req, res) => {
  const { name, description } = req.body;
  try { db.prepare('INSERT INTO license_group (name, description) VALUES (?,?)').run(name, description || ''); res.json({ code: 0, message: '已创建' }); }
  catch (e) { res.json({ code: 400, message: e.message }); }
});
admin.put('/license-groups/:id', (req, res) => {
  const { name, description } = req.body;
  db.prepare('UPDATE license_group SET name=?, description=? WHERE id=?').run(name, description || '', req.params.id);
  res.json({ code: 0, message: '已更新' });
});
admin.delete('/license-groups/:id', (req, res) => {
  db.prepare('DELETE FROM license_group WHERE id=?').run(req.params.id);
  res.json({ code: 0, message: '已删除' });
});

// --- 用户管理（机器码）---
// One actively-bound machine code = one user. Data is the real device_bindings
// from michael-vip's MySQL, enriched with the latest IP from activation_logs.
async function handleMachineUsers(req, res) {
  const { page = 1, pageSize = 10, status, search } = req.query;
  try {
    let where = 'b.is_active = 1';
    const params = [];
    if (search) {
      where += ' AND (b.machine_id LIKE ? OR b.machine_name LIKE ? OR k.license_key LIKE ?)';
      const s = `%${search}%`; params.push(s, s, s);
    }
    if (status === 'active') where += ' AND b.last_heartbeat > DATE_SUB(NOW(), INTERVAL 7 DAY)';
    else if (status === 'expired') where += ' AND (b.last_heartbeat IS NULL OR b.last_heartbeat <= DATE_SUB(NOW(), INTERVAL 7 DAY))';
    const [{ c: total }] = await mvQuery(
      `SELECT COUNT(*) AS c FROM device_bindings b JOIN license_keys k ON k.id = b.license_id WHERE ${where}`, params);
    const offset = (Math.max(1, +page) - 1) * (+pageSize);
    const rows = await mvQuery(`
      SELECT b.id, b.machine_id, b.machine_name, b.last_heartbeat, b.activated_at, b.expires_at,
             k.license_key, k.key_type, k.status AS license_status,
             (SELECT l.ip_address FROM activation_logs l WHERE l.machine_id = b.machine_id ORDER BY l.created_at DESC LIMIT 1) AS ip,
             (SELECT l.created_at FROM activation_logs l WHERE l.machine_id = b.machine_id ORDER BY l.created_at DESC LIMIT 1) AS last_seen
      FROM device_bindings b JOIN license_keys k ON k.id = b.license_id
      WHERE ${where} ORDER BY b.last_heartbeat DESC LIMIT ? OFFSET ?`, [...params, +pageSize, offset]);
    const now = Date.now();
    const list = rows.map(r => {
      const online = r.last_heartbeat && (now - new Date(r.last_heartbeat).getTime() < 7 * 864e5);
      const mid = r.machine_id || '';
      return {
        id: r.id,
        machine_id: mid,
        machine_id_short: mid.length > 20 ? mid.slice(0, 20) + '…' : mid,
        machine_name: r.machine_name || '-',
        email: r.machine_name || mid.slice(0, 16),       // back-compat for legacy templates
        license_key: r.license_key,
        key_type: r.key_type,
        ip: r.ip || '-',
        status: online ? 'active' : 'expired',
        last_heartbeat: r.last_heartbeat,
        last_seen: r.last_seen,
        activated_at: r.activated_at,
        expires_at: r.expires_at
      };
    });
    res.json({ code: 0, data: { list, total, page: +page, pageSize: +pageSize, source: 'michael-vip' } });
  } catch (e) {
    res.json({ code: 0, data: { list: [], total: 0, page: +page, pageSize: +pageSize, error: e.message } });
  }
}
admin.get('/accounts', handleMachineUsers);
admin.get('/machines', handleMachineUsers);

admin.post('/accounts', (req, res) => {
  const { email, token, workos_token, note } = req.body;
  try { db.prepare('INSERT INTO cursor_account (email, token, workos_token, note) VALUES (?,?,?,?)').run(email, token || '', workos_token || '', note || ''); res.json({ code: 0, message: '已添加' }); }
  catch (e) { res.json({ code: 400, message: e.message }); }
});

admin.put('/accounts/:id', (req, res) => {
  const { email, token, workos_token, status, note } = req.body;
  db.prepare('UPDATE cursor_account SET email=?, token=?, workos_token=?, status=?, note=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(email, token || '', workos_token || '', status || 'active', note || '', req.params.id);
  res.json({ code: 0, message: '已更新' });
});

admin.delete('/accounts/:id', (req, res) => {
  db.prepare('DELETE FROM cursor_account WHERE id=?').run(req.params.id);
  res.json({ code: 0, message: '已删除' });
});

admin.post('/accounts/import', (req, res) => {
  const { accounts } = req.body;
  if (!Array.isArray(accounts)) return res.json({ code: 400, message: '格式错误' });
  const stmt = db.prepare('INSERT OR IGNORE INTO cursor_account (email, token, workos_token, note) VALUES (?,?,?,?)');
  const tx = db.transaction(() => { for (const a of accounts) stmt.run(a.email, a.token || '', a.workos_token || '', a.note || ''); });
  tx();
  res.json({ code: 0, message: `已导入 ${accounts.length} 个` });
});

// --- Device Blacklist ---
admin.get('/device-blacklist', (req, res) => {
  const { status } = req.query;
  let data;
  if (status) data = db.prepare('SELECT * FROM device_blacklist WHERE status = ? ORDER BY id DESC').all(status);
  else data = db.prepare('SELECT * FROM device_blacklist ORDER BY id DESC').all();
  res.json({ code: 0, data });
});

admin.post('/device-blacklist', (req, res) => {
  const { device_hash, reason } = req.body;
  db.prepare('INSERT INTO device_blacklist (device_hash, reason) VALUES (?,?)').run(device_hash, reason || 'admin ban');
  res.json({ code: 0, message: '已封禁' });
});

admin.delete('/device-blacklist/:hash', (req, res) => {
  db.prepare("UPDATE device_blacklist SET status='inactive', unbanned_at=CURRENT_TIMESTAMP WHERE device_hash=? AND status='active'").run(decodeURIComponent(req.params.hash));
  db.prepare("DELETE FROM security_event WHERE device_hash=?").run(decodeURIComponent(req.params.hash));
  db.prepare("DELETE FROM bundle_tamper_log WHERE device_hash=?").run(decodeURIComponent(req.params.hash));
  res.json({ code: 0, message: '已解封' });
});

// --- IP Blacklist ---
admin.get('/ip-blacklist', (req, res) => {
  const { page = 1, pageSize = 10, search } = req.query;
  let where = '1=1'; const params = [];
  if (search) { where += ' AND (ip LIKE ? OR reason LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
  const total = db.prepare(`SELECT COUNT(*) as c FROM ip_blacklist WHERE ${where}`).get(...params).c;
  const list = db.prepare(`SELECT * FROM ip_blacklist WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, +pageSize, (+page - 1) * +pageSize);
  res.json({ code: 0, data: { list, total } });
});
admin.post('/ip-blacklist', (req, res) => {
  const { ip, reason } = req.body;
  db.prepare('INSERT INTO ip_blacklist (ip, reason) VALUES (?,?)').run(ip, reason || 'manual');
  res.json({ code: 0, message: '已添加' });
});
admin.post('/ip-blacklist/:id/toggle', (req, res) => {
  const row = db.prepare('SELECT status FROM ip_blacklist WHERE id=?').get(req.params.id);
  if (!row) return res.json({ code: 404, message: '不存在' });
  const next = row.status === 'active' ? 'inactive' : 'active';
  db.prepare('UPDATE ip_blacklist SET status=? WHERE id=?').run(next, req.params.id);
  res.json({ code: 0, message: '已切换' });
});
admin.delete('/ip-blacklist/:id', (req, res) => {
  db.prepare('DELETE FROM ip_blacklist WHERE id=?').run(req.params.id);
  res.json({ code: 0, message: '已删除' });
});

// --- Security Events ---
// 安全事件：真实读取 michael-vip 的拒绝记录（无效卡密 / 超设备数 / 封禁等失败/异常授权）。
admin.get('/security-events', async (req, res) => {
  const { page = 1, pageSize = 20, event_type, device_hash, ip } = req.query;
  try {
    let where = "l.action = 'reject'"; const params = [];
    if (device_hash) { where += ' AND l.machine_id LIKE ?'; params.push(`%${device_hash}%`); }
    if (ip) { where += ' AND l.ip_address LIKE ?'; params.push(`%${ip}%`); }
    if (event_type) { where += " AND JSON_UNQUOTE(JSON_EXTRACT(l.details, '$.reason')) = ?"; params.push(event_type); }
    const cnt = await mvQuery(`SELECT COUNT(*) AS c FROM activation_logs l WHERE ${where}`, params);
    const total = cnt[0] ? cnt[0].c : 0;
    const rows = await mvQuery(
      `SELECT l.id, l.machine_id, l.ip_address, l.details, l.created_at, k.license_key
       FROM activation_logs l LEFT JOIN license_keys k ON k.id = l.license_id
       WHERE ${where} ORDER BY l.id DESC LIMIT ? OFFSET ?`,
      [...params, +pageSize, (+page - 1) * +pageSize]
    );
    const list = rows.map(r => {
      const d = (r.details && typeof r.details === 'object') ? r.details : {};
      return {
        id: r.id,
        created_at: r.created_at,
        event_type: d.reason || d.action || 'reject',
        device_hash: r.machine_id || '',
        ip: cleanIp(r.ip_address),
        detail: fmtDetails(r.details),
        extension_version: '',
        linked_license: r.license_key || ''
      };
    });
    let stats = [];
    try {
      stats = await mvQuery(
        `SELECT JSON_UNQUOTE(JSON_EXTRACT(details, '$.reason')) AS event_type, COUNT(*) AS count, COUNT(DISTINCT machine_id) AS devices
         FROM activation_logs WHERE action = 'reject' GROUP BY event_type ORDER BY count DESC`
      );
      stats = stats.map(s => ({ event_type: s.event_type || 'reject', count: s.count, devices: s.devices }));
    } catch {}
    res.json({ code: 0, data: { list, total, stats } });
  } catch (e) { res.json({ code: 0, data: { list: [], total: 0, stats: [], error: e.message } }); }
});
admin.delete('/security-events/:id', async (req, res) => {
  try { await mvQuery("DELETE FROM activation_logs WHERE id = ? AND action = 'reject'", [req.params.id]); res.json({ code: 0, message: '已删除' }); }
  catch (e) { res.json({ code: 400, message: e.message }); }
});
admin.post('/security-events/batch-delete', async (req, res) => {
  const { ids, all: deleteAll, filter } = req.body;
  try {
    if (deleteAll) {
      let where = "action = 'reject'"; const params = [];
      if (filter && filter.device_hash) { where += ' AND machine_id LIKE ?'; params.push(`%${filter.device_hash}%`); }
      if (filter && filter.ip) { where += ' AND ip_address LIKE ?'; params.push(`%${filter.ip}%`); }
      if (filter && filter.event_type) { where += " AND JSON_UNQUOTE(JSON_EXTRACT(details, '$.reason')) = ?"; params.push(filter.event_type); }
      await mvQuery(`DELETE FROM activation_logs WHERE ${where}`, params);
    } else if (ids && ids.length) {
      const ph = ids.map(() => '?').join(',');
      await mvQuery(`DELETE FROM activation_logs WHERE action = 'reject' AND id IN (${ph})`, ids);
    }
    res.json({ code: 0, message: '已删除' });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

// --- Device Poison ---
admin.get('/device-poison', (req, res) => {
  const list = db.prepare('SELECT * FROM device_poison ORDER BY id DESC').all();
  const scriptTypes = ['stub', 'crash', 'delay', 'watermark'];
  res.json({ code: 0, data: { list, scriptTypes } });
});
admin.post('/device-poison', (req, res) => {
  const { device_hash, script_type, reason } = req.body;
  db.prepare('INSERT INTO device_poison (device_hash, script_type, reason) VALUES (?,?,?)').run(device_hash, script_type || 'stub', reason || '');
  res.json({ code: 0, message: '已添加' });
});

// --- Versions (shared michael-vip MySQL: app_versions) ---
admin.get('/versions', async (req, res) => {
  try {
    const rows = await mvQuery('SELECT * FROM app_versions ORDER BY id DESC LIMIT 200');
    const list = rows.map(v => ({
      id: v.id, version: v.version, changelog: v.changelog || '',
      download_url: v.download_url || '', force_update: v.force_update,
      channel: v.channel || 'stable', status: v.status || 'published',
      download_count: v.download_count || 0, created_at: v.created_at, published_at: v.created_at,
      target_tiers: [], file_size: 0, platform: 'all'
    }));
    res.json({ code: 0, data: { list } });
  } catch (e) { res.json({ code: 0, data: { list: [], error: e.message } }); }
});
admin.post('/versions/publish', async (req, res) => {
  const { version, download_url, changelog, force_update, channel } = req.body;
  if (!version) return res.json({ code: 400, message: '缺少版本号' });
  try {
    await mvQuery('INSERT INTO app_versions (version, changelog, download_url, force_update, channel, status) VALUES (?,?,?,?,?,?)',
      [version, changelog || '', download_url || '', force_update ? 1 : 0, channel || 'stable', 'published']);
    res.json({ code: 0, message: '已发布' });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});
admin.post('/versions/toggle', async (req, res) => {
  const { id, status } = req.body;
  try { await mvQuery('UPDATE app_versions SET status=? WHERE id=?', [status, id]); res.json({ code: 0, message: '已切换' }); }
  catch (e) { res.json({ code: 400, message: e.message }); }
});
admin.delete('/versions/:id', async (req, res) => {
  try { await mvQuery('DELETE FROM app_versions WHERE id=?', [req.params.id]); res.json({ code: 0, message: '已删除' }); }
  catch (e) { res.json({ code: 400, message: e.message }); }
});

// --- Agents ---
admin.get('/agents', (req, res) => {
  const data = db.prepare("SELECT id, username, display_name, role, permissions, note, status, created_at FROM admin_user WHERE role != 'super' ORDER BY id DESC").all();
  res.json({ code: 0, data: data.map(a => ({ ...a, permissions: JSON.parse(a.permissions || '[]') })) });
});
admin.post('/agents', (req, res) => {
  const { username, display_name, password, permissions, note, status } = req.body;
  if (!password || password.length < 6) return res.json({ code: 400, message: '密码至少6位' });
  try {
    db.prepare('INSERT INTO admin_user (username, password_hash, display_name, role, permissions, note, status) VALUES (?,?,?,?,?,?,?)').run(username, bcrypt.hashSync(password, 10), display_name || '', 'agent', JSON.stringify(permissions || []), note || '', status || 'active');
    res.json({ code: 0, message: '已创建' });
  } catch (e) { res.json({ code: 400, message: '用户名已存在' }); }
});
admin.put('/agents/:id', (req, res) => {
  const { display_name, permissions, note, status } = req.body;
  db.prepare('UPDATE admin_user SET display_name=?, permissions=?, note=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(display_name || '', JSON.stringify(permissions || []), note || '', status || 'active', req.params.id);
  res.json({ code: 0, message: '已更新' });
});
admin.delete('/agents/:id', (req, res) => {
  db.prepare("DELETE FROM admin_user WHERE id=? AND role != 'super'").run(req.params.id);
  res.json({ code: 0, message: '已删除' });
});
admin.post('/agents/:id/password', (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.json({ code: 400, message: '密码至少6位' });
  db.prepare('UPDATE admin_user SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(bcrypt.hashSync(password, 10), req.params.id);
  res.json({ code: 0, message: '密码已修改' });
});

// --- Settings ---
admin.get('/settings/:key', (req, res) => {
  const row = db.prepare('SELECT value FROM settings WHERE key=?').get(req.params.key);
  res.json({ code: 0, data: row ? JSON.parse(row.value) : {} });
});
admin.put('/settings/:key', (req, res) => {
  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)').run(req.params.key, JSON.stringify(req.body));
  if (req.params.key === 'smtp') { smtpTransporter = null; getSmtpTransporter(); }
  if (req.params.key === 'tasks') { setupCronJobs(); }
  res.json({ code: 0, message: '已保存' });
});
admin.post('/settings/smtp/test', async (req, res) => {
  try {
    const transporter = getSmtpTransporter();
    if (!transporter) return res.json({ code: 400, message: 'SMTP 未配置或未启用，请先保存 SMTP 设置' });
    const row = db.prepare("SELECT value FROM settings WHERE key='smtp'").get();
    const cfg = JSON.parse(row.value);
    const testTo = req.body.to || cfg.notifyTo || cfg.user;
    if (!testTo) return res.json({ code: 400, message: '缺少收件人地址' });
    await transporter.sendMail({
      from: `"Michael Cursor VIP" <${cfg.user}>`,
      to: testTo,
      subject: '✅ SMTP 测试邮件 - Michael Cursor VIP',
      html: `<div style="font-family:sans-serif;padding:20px;background:#f8f9fa;border-radius:8px;">
        <h2 style="color:#1a73e8;">SMTP 配置成功</h2>
        <p>这是一封来自 <b>Michael Cursor VIP</b> 管理后台的测试邮件。</p>
        <p style="color:#5f6368;font-size:13px;">发送时间：${new Date().toLocaleString('zh-CN')}</p>
      </div>`
    });
    res.json({ code: 0, message: `测试邮件已发送至 ${testTo}` });
  } catch (e) {
    res.json({ code: 500, message: `发送失败：${e.message}` });
  }
});

admin.post('/settings/tasks/trigger', (req, res) => {
  try {
    const results = {};
    const expiredKeys = db.prepare("UPDATE license_key SET status='expired' WHERE status='active' AND expires_at IS NOT NULL AND expires_at < datetime('now')").run();
    results.expiredKeys = expiredKeys.changes;
    const expiredAccounts = db.prepare("UPDATE cursor_account SET status='expired' WHERE status='active' AND billing_cycle_end IS NOT NULL AND billing_cycle_end < datetime('now')").run();
    results.expiredAccounts = expiredAccounts.changes;
    const ts = Math.floor(Date.now() / 1000) - 86400;
    const nonces = db.prepare('DELETE FROM used_nonce WHERE ts < ?').run(ts);
    results.cleanedNonces = nonces.changes;
    const suspicious = db.prepare("SELECT ip, COUNT(*) as cnt FROM license_verify_log WHERE success=0 AND created_at > datetime('now','-1 hour') GROUP BY ip HAVING cnt >= 10").all();
    results.suspiciousIps = suspicious.length;
    for (const s of suspicious) {
      const exists = db.prepare("SELECT id FROM ip_blacklist WHERE ip=? AND status='active'").get(s.ip);
      if (!exists) db.prepare("INSERT INTO ip_blacklist (ip, reason) VALUES (?, ?)").run(s.ip, `auto-ban: ${s.cnt} failed verifications`);
    }
    setupCronJobs();
    res.json({ code: 0, message: `任务已执行`, data: results });
  } catch (e) {
    res.json({ code: 500, message: `执行失败：${e.message}` });
  }
});

// --- Announcements (shared michael-vip MySQL: app_announcements) ---
admin.get('/announcements', async (req, res) => {
  const { page = 1, pageSize = 10 } = req.query;
  try {
    const [{ c: total }] = await mvQuery('SELECT COUNT(*) AS c FROM app_announcements');
    const offset = (Math.max(1, +page) - 1) * (+pageSize);
    const rows = await mvQuery('SELECT * FROM app_announcements ORDER BY id DESC LIMIT ? OFFSET ?', [+pageSize, offset]);
    const list = rows.map(a => ({ id: a.id, title: a.title || '', content: a.content || '', type: a.level || 'info', status: a.disabled ? 'disabled' : 'active', created_at: a.created_at }));
    res.json({ code: 0, data: { list, total } });
  } catch (e) { res.json({ code: 0, data: { list: [], total: 0, error: e.message } }); }
});
admin.post('/announcements', async (req, res) => {
  const { title, content, type } = req.body;
  try { await mvQuery('INSERT INTO app_announcements (title, content, level) VALUES (?,?,?)', [title || '', content || '', type || 'info']); res.json({ code: 0, message: '已创建' }); }
  catch (e) { res.json({ code: 400, message: e.message }); }
});
admin.put('/announcements/:id', async (req, res) => {
  const { title, content, type, status } = req.body;
  try { await mvQuery('UPDATE app_announcements SET title=?, content=?, level=?, disabled=? WHERE id=?', [title || '', content || '', type || 'info', status === 'disabled' ? 1 : 0, req.params.id]); res.json({ code: 0, message: '已更新' }); }
  catch (e) { res.json({ code: 400, message: e.message }); }
});
admin.delete('/announcements/:id', async (req, res) => {
  try { await mvQuery('DELETE FROM app_announcements WHERE id=?', [req.params.id]); res.json({ code: 0, message: '已删除' }); }
  catch (e) { res.json({ code: 400, message: e.message }); }
});

// --- Logs ---
// 下载日志：真实读取 michael-vip 的 download_logs（443 /dl/ 下载埋点）。
admin.get('/logs', async (req, res) => {
  const { page = 1, pageSize = 20 } = req.query;
  try {
    const cnt = await mvQuery('SELECT COUNT(*) AS c FROM download_logs');
    const total = cnt[0] ? cnt[0].c : 0;
    const rows = await mvQuery('SELECT id, file, version, channel, ip, created_at FROM download_logs ORDER BY id DESC LIMIT ? OFFSET ?', [+pageSize, (+page - 1) * +pageSize]);
    const list = rows.map(r => ({
      id: r.id, type: r.channel || 'vsix', channel: r.channel || 'vsix',
      version: r.version || '', license_key: '', device_id: '',
      ip: cleanIp(r.ip), created_at: r.created_at
    }));
    res.json({ code: 0, data: { list, total } });
  } catch (e) { res.json({ code: 0, data: { list: [], total: 0, error: e.message } }); }
});
admin.get('/operation-logs', (req, res) => {
  const { page = 1, pageSize = 20, module: mod, actor, action } = req.query;
  let where = '1=1'; const params = [];
  if (mod) { where += ' AND module = ?'; params.push(mod); }
  if (actor) { where += ' AND actor LIKE ?'; params.push(`%${actor}%`); }
  if (action) { where += ' AND action = ?'; params.push(action); }
  const total = db.prepare(`SELECT COUNT(*) as c FROM operation_log WHERE ${where}`).get(...params).c;
  const list = db.prepare(`SELECT * FROM operation_log WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, +pageSize, (+page - 1) * +pageSize);
  res.json({ code: 0, data: { list, total } });
});
admin.get('/admin-login-logs', (req, res) => {
  const { page = 1, pageSize = 20 } = req.query;
  const total = db.prepare('SELECT COUNT(*) as c FROM admin_login_log').get().c;
  const list = db.prepare('SELECT * FROM admin_login_log ORDER BY id DESC LIMIT ? OFFSET ?').all(+pageSize, (+page - 1) * +pageSize);
  let suspiciousIps = [];
  try { suspiciousIps = db.prepare("SELECT ip, COUNT(*) as cnt FROM admin_login_log WHERE success=0 AND created_at > datetime('now','-1 day') GROUP BY ip HAVING cnt >= 3 ORDER BY cnt DESC LIMIT 10").all(); } catch {}
  res.json({ code: 0, data: { list, total, suspiciousIps } });
});
// 授权记录：真实读取 michael-vip 的 activation_logs（激活/校验/解绑/拒绝全部审计流水）。
admin.get('/verify-logs', async (req, res) => {
  const { page = 1, pageSize = 20, ip, license_key, device_id, action, success } = req.query;
  try {
    let where = '1=1'; const params = [];
    if (ip) { where += ' AND l.ip_address LIKE ?'; params.push(`%${ip}%`); }
    if (license_key) { where += ' AND k.license_key LIKE ?'; params.push(`%${license_key}%`); }
    if (device_id) { where += ' AND l.machine_id LIKE ?'; params.push(`%${device_id}%`); }
    if (action) { where += ' AND l.action = ?'; params.push(action); }
    if (success !== undefined && success !== '') {
      where += (+success === 1) ? " AND l.action <> 'reject'" : " AND l.action = 'reject'";
    }
    const cnt = await mvQuery(`SELECT COUNT(*) AS c FROM activation_logs l LEFT JOIN license_keys k ON k.id = l.license_id WHERE ${where}`, params);
    const total = cnt[0] ? cnt[0].c : 0;
    const rows = await mvQuery(
      `SELECT l.id, l.action, l.machine_id, l.ip_address, l.details, l.created_at, k.license_key
       FROM activation_logs l LEFT JOIN license_keys k ON k.id = l.license_id
       WHERE ${where} ORDER BY l.id DESC LIMIT ? OFFSET ?`,
      [...params, +pageSize, (+page - 1) * +pageSize]
    );
    const list = rows.map(r => ({
      id: r.id,
      license_key: r.license_key || '',
      action: r.action,
      success: r.action !== 'reject' ? 1 : 0,
      version: '',
      device_id: r.machine_id || '',
      ip: cleanIp(r.ip_address),
      message: fmtDetails(r.details),
      created_at: r.created_at
    }));
    res.json({ code: 0, data: { list, total } });
  } catch (e) { res.json({ code: 0, data: { list: [], total: 0, error: e.message } }); }
});
admin.get('/bundle-tamper-log', (req, res) => {
  const { page = 1, pageSize = 20, action, version, device_id, ip, hash } = req.query;
  let where = '1=1'; const params = [];
  if (action) { where += ' AND action = ?'; params.push(action); }
  if (version) { where += ' AND version LIKE ?'; params.push(`%${version}%`); }
  if (device_id) { where += ' AND device_hash LIKE ?'; params.push(`%${device_id}%`); }
  if (ip) { where += ' AND ip LIKE ?'; params.push(`%${ip}%`); }
  if (hash) { where += ' AND bundle_hash LIKE ?'; params.push(`%${hash}%`); }
  const total = db.prepare(`SELECT COUNT(*) as c FROM bundle_tamper_log WHERE ${where}`).get(...params).c;
  const list = db.prepare(`SELECT * FROM bundle_tamper_log WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, +pageSize, (+page - 1) * +pageSize);
  let totalDevices = 0, stats = [];
  try { totalDevices = db.prepare('SELECT COUNT(DISTINCT device_hash) as c FROM bundle_tamper_log').get().c; } catch {}
  try { stats = db.prepare('SELECT action, COUNT(*) as count FROM bundle_tamper_log GROUP BY action ORDER BY count DESC').all(); } catch {}
  res.json({ code: 0, data: { list, total, totalDevices, stats } });
});
admin.get('/report-logs', (req, res) => {
  const { page = 1, pageSize = 20, email } = req.query;
  let where = '1=1'; const params = [];
  if (email) { where += ' AND email LIKE ?'; params.push(`%${email}%`); }
  const total = db.prepare(`SELECT COUNT(*) as c FROM report_log WHERE ${where}`).get(...params).c;
  const list = db.prepare(`SELECT * FROM report_log WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, +pageSize, (+page - 1) * +pageSize);
  res.json({ code: 0, data: { list, total } });
});

// --- Permission Catalog ---
admin.get('/permission-catalog', (req, res) => {
  res.json({ code: 0, data: {
    catalog: [
      { module: 'dashboard', label: '仪表盘', actions: [{ key: 'read', label: '查看' }] },
      { module: 'licenses', label: '卡密管理', actions: [
        { key: 'read', label: '查看' }, { key: 'write', label: '创建/编辑' }, { key: 'delete', label: '删除' },
        { key: 'extend', label: '续期' }, { key: 'unbind', label: '解绑' }, { key: 'toggle', label: '启用/禁用' },
        { key: 'permission', label: '权限设置' }, { key: 'reset_unbind', label: '重置解绑' },
        { key: 'full_reset', label: '完全重置' }, { key: 'reset_quota', label: '重置配额' }, { key: 'group', label: '分组管理' },
      ]},
      { module: 'accounts', label: '账号管理', actions: [{ key: 'read', label: '查看' }, { key: 'write', label: '编辑' }, { key: 'delete', label: '删除' }] },
      { module: 'versions', label: '版本管理', actions: [{ key: 'read', label: '查看' }, { key: 'write', label: '发布' }] },
      { module: 'announcements', label: '系统公告', actions: [{ key: 'read', label: '查看' }, { key: 'write', label: '编辑' }] },
      { module: 'security_events', label: '安全事件', actions: [{ key: 'read', label: '查看' }, { key: 'ban', label: '封禁' }] },
      { module: 'ip_blacklist', label: 'IP 黑名单', actions: [{ key: 'read', label: '查看' }, { key: 'write', label: '操作' }] },
      { module: 'verify_logs', label: '授权记录', actions: [{ key: 'read', label: '查看' }] },
      { module: 'download_logs', label: '下载日志', actions: [{ key: 'read', label: '查看' }] },
      { module: 'admin_logs', label: '登录日志', actions: [{ key: 'read', label: '查看' }] },
      { module: 'installer', label: '安装管理', actions: [{ key: 'read', label: '查看' }, { key: 'write', label: '操作' }] },
      { module: 'operation_logs', label: '操作日志', actions: [{ key: 'read', label: '查看' }] },
      { module: 'device_poison', label: '设备投毒', actions: [{ key: 'read', label: '查看' }, { key: 'write', label: '操作' }] },
    ],
    actionLabels: { read: '查看', write: '操作', delete: '删除', ban: '封禁', extend: '续期', unbind: '解绑', toggle: '启用/禁用', permission: '权限', reset_unbind: '重置解绑', full_reset: '完全重置', reset_quota: '重置配额', group: '分组' },
  }});
});

// --- Cloud Service ---
admin.get('/cloud/overview', (req, res) => {
  try {
    const instances = db.prepare('SELECT * FROM cloud_instance ORDER BY id DESC').all();
    const totalSessions = db.prepare("SELECT COUNT(*) as c FROM cloud_session WHERE status='active'").get().c;
    const totalRequests24h = db.prepare("SELECT COUNT(*) as c FROM cloud_proxy_log WHERE created_at > datetime('now','-1 day')").get().c;
    const avgResponseTime = db.prepare("SELECT COALESCE(AVG(response_time_ms),0) as avg FROM cloud_proxy_log WHERE created_at > datetime('now','-1 hour')").get().avg;
    const successRate = db.prepare("SELECT COALESCE(AVG(success)*100,0) as rate FROM cloud_proxy_log WHERE created_at > datetime('now','-1 hour')").get().rate;
    const onlineCount = instances.filter(i => i.status === 'online').length;
    res.json({ code: 0, data: {
      instances, summary: {
        totalInstances: instances.length, onlineInstances: onlineCount,
        offlineInstances: instances.length - onlineCount,
        totalActiveSessions: totalSessions, totalRequests24h,
        avgResponseTimeMs: Math.round(avgResponseTime), successRate: Math.round(successRate * 10) / 10,
      }
    }});
  } catch (e) { res.json({ code: 0, data: { instances: [], summary: { totalInstances: 0, onlineInstances: 0, offlineInstances: 0, totalActiveSessions: 0, totalRequests24h: 0, avgResponseTimeMs: 0, successRate: 0 } } }); }
});

admin.get('/cloud/sessions', (req, res) => {
  const { page = 1, pageSize = 20, instance_id, status, ip } = req.query;
  let where = '1=1'; const params = [];
  if (instance_id) { where += ' AND instance_id = ?'; params.push(instance_id); }
  if (status) { where += ' AND status = ?'; params.push(status); }
  if (ip) { where += ' AND client_ip LIKE ?'; params.push(`%${ip}%`); }
  try {
    const total = db.prepare(`SELECT COUNT(*) as c FROM cloud_session WHERE ${where}`).get(...params).c;
    const list = db.prepare(`SELECT * FROM cloud_session WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, +pageSize, (+page - 1) * +pageSize);
    res.json({ code: 0, data: { list, total } });
  } catch (e) { res.json({ code: 0, data: { list: [], total: 0 } }); }
});

admin.get('/cloud/logs', (req, res) => {
  const { page = 1, pageSize = 20, instance_id, success, ip } = req.query;
  let where = '1=1'; const params = [];
  if (instance_id) { where += ' AND instance_id = ?'; params.push(instance_id); }
  if (success !== undefined && success !== '') { where += ' AND success = ?'; params.push(+success); }
  if (ip) { where += ' AND client_ip LIKE ?'; params.push(`%${ip}%`); }
  try {
    const total = db.prepare(`SELECT COUNT(*) as c FROM cloud_proxy_log WHERE ${where}`).get(...params).c;
    const list = db.prepare(`SELECT * FROM cloud_proxy_log WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...params, +pageSize, (+page - 1) * +pageSize);
    res.json({ code: 0, data: { list, total } });
  } catch (e) { res.json({ code: 0, data: { list: [], total: 0 } }); }
});

admin.post('/cloud/instances', (req, res) => {
  const { name, server_ip, proxy_port, region, max_sessions, note } = req.body;
  if (!server_ip) return res.json({ code: 400, message: '缺少服务器 IP' });
  try {
    db.prepare('INSERT INTO cloud_instance (name, server_ip, proxy_port, region, max_sessions, note) VALUES (?,?,?,?,?,?)').run(name || '', server_ip, proxy_port || 8901, region || '', max_sessions || 50, note || '');
    res.json({ code: 0, message: '已添加' });
  } catch (e) { res.json({ code: 400, message: e.message }); }
});

admin.put('/cloud/instances/:id', (req, res) => {
  const { name, server_ip, proxy_port, region, max_sessions, note, status } = req.body;
  const sets = []; const params = [];
  if (name !== undefined) { sets.push('name=?'); params.push(name); }
  if (server_ip !== undefined) { sets.push('server_ip=?'); params.push(server_ip); }
  if (proxy_port !== undefined) { sets.push('proxy_port=?'); params.push(proxy_port); }
  if (region !== undefined) { sets.push('region=?'); params.push(region); }
  if (max_sessions !== undefined) { sets.push('max_sessions=?'); params.push(max_sessions); }
  if (note !== undefined) { sets.push('note=?'); params.push(note); }
  if (status !== undefined) { sets.push('status=?'); params.push(status); }
  if (sets.length === 0) return res.json({ code: 400, message: '无修改' });
  sets.push('updated_at=CURRENT_TIMESTAMP');
  params.push(req.params.id);
  db.prepare(`UPDATE cloud_instance SET ${sets.join(',')} WHERE id=?`).run(...params);
  res.json({ code: 0, message: '已更新' });
});

admin.delete('/cloud/instances/:id', (req, res) => {
  db.prepare('DELETE FROM cloud_session WHERE instance_id=?').run(req.params.id);
  db.prepare('DELETE FROM cloud_instance WHERE id=?').run(req.params.id);
  res.json({ code: 0, message: '已删除' });
});

admin.post('/cloud/instances/:id/check', (req, res) => {
  const inst = db.prepare('SELECT * FROM cloud_instance WHERE id=?').get(req.params.id);
  if (!inst) return res.json({ code: 404, message: '实例不存在' });
  const http = require('http');
  const checkUrl = `http://${inst.server_ip}:${inst.proxy_port}/health`;
  const check = http.get(checkUrl, { timeout: 5000 }, (resp) => {
    let body = '';
    resp.on('data', c => body += c);
    resp.on('end', () => {
      try {
        const j = JSON.parse(body);
        const newStatus = j.status === 'ok' ? 'online' : 'error';
        db.prepare('UPDATE cloud_instance SET status=?, last_heartbeat=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(newStatus, inst.id);
        res.json({ code: 0, data: { status: newStatus, response: j } });
      } catch (e) {
        db.prepare("UPDATE cloud_instance SET status='error', updated_at=CURRENT_TIMESTAMP WHERE id=?").run(inst.id);
        res.json({ code: 0, data: { status: 'error', message: 'Invalid response' } });
      }
    });
  });
  check.on('error', (e) => {
    db.prepare("UPDATE cloud_instance SET status='offline', updated_at=CURRENT_TIMESTAMP WHERE id=?").run(inst.id);
    res.json({ code: 0, data: { status: 'offline', message: e.message } });
  });
  check.on('timeout', () => {
    check.destroy();
    db.prepare("UPDATE cloud_instance SET status='offline', updated_at=CURRENT_TIMESTAMP WHERE id=?").run(inst.id);
    res.json({ code: 0, data: { status: 'offline', message: 'timeout' } });
  });
});

admin.post('/cloud/heartbeat', (req, res) => {
  const { server_ip, proxy_port, active_sessions, cpu_usage, memory_usage, sessions } = req.body;
  if (!server_ip) return res.json({ code: 400, message: '缺少 server_ip' });
  const inst = db.prepare('SELECT * FROM cloud_instance WHERE server_ip=? AND proxy_port=?').get(server_ip, proxy_port || 8901);
  if (!inst) return res.json({ code: 404, message: '实例未注册' });
  db.prepare("UPDATE cloud_instance SET status='online', last_heartbeat=CURRENT_TIMESTAMP, active_sessions=?, cpu_usage=?, memory_usage=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
    .run(active_sessions || 0, cpu_usage || 0, memory_usage || 0, inst.id);
  if (sessions && Array.isArray(sessions)) {
    db.prepare("UPDATE cloud_session SET status='disconnected', disconnected_at=CURRENT_TIMESTAMP WHERE instance_id=? AND status='active'").run(inst.id);
    const upsert = db.prepare("INSERT OR REPLACE INTO cloud_session (instance_id, license_key, device_hash, client_ip, account_email, status, requests_count, last_request_at, connected_at) VALUES (?,?,?,?,?,?,?,CURRENT_TIMESTAMP,COALESCE((SELECT connected_at FROM cloud_session WHERE instance_id=? AND device_hash=? AND status='active'),CURRENT_TIMESTAMP))");
    for (const s of sessions) {
      upsert.run(inst.id, s.license_key || '', s.device_hash || '', s.client_ip || '', s.account_email || '', 'active', s.requests_count || 0, inst.id, s.device_hash || '');
    }
  }
  res.json({ code: 0, message: 'heartbeat received' });
});

// --- PKCE ---
admin.get('/pkce', (req, res) => {
  const { page = 1, pageSize = 10 } = req.query;
  const total = db.prepare('SELECT COUNT(*) as c FROM pkce_token').get().c;
  const list = db.prepare('SELECT * FROM pkce_token ORDER BY id DESC LIMIT ? OFFSET ?').all(+pageSize, (+page - 1) * +pageSize);
  res.json({ code: 0, data: { list, total } });
});
admin.post('/pkce/batch-delete', (req, res) => {
  const { ids } = req.body;
  if (ids) { const stmt = db.prepare('DELETE FROM pkce_token WHERE id=?'); for (const id of ids) stmt.run(id); }
  res.json({ code: 0, message: '已删除' });
});

// ═══ Login (no auth required) ═══
app.post('/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM admin_user WHERE username = ? AND status = ?').get(username, 'active');
  db.prepare('INSERT INTO admin_login_log (username, ip, success, message) VALUES (?,?,?,?)').run(username || '', req.ip, user && bcrypt.compareSync(password, user.password_hash) ? 1 : 0, '');
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ code: 401, message: '用户名或密码错误' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, permissions: JSON.parse(user.permissions || '[]') }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ code: 0, data: { token, role: user.role, permissions: JSON.parse(user.permissions || '[]'), username: user.username } });
});

// Mount admin routes
app.use('/admin', admin);

// Cloud heartbeat (no auth — called by proxy service internally)
app.post('/internal/cloud/heartbeat', (req, res) => {
  const clientIp = req.ip || req.socket.remoteAddress || '';
  if (!clientIp.includes('127.0.0.1') && !clientIp.includes('::1') && !clientIp.includes('localhost')) {
    return res.status(403).json({ code: 403, message: 'internal only' });
  }
  const { server_ip, proxy_port, active_sessions, cpu_usage, memory_usage, sessions } = req.body;
  if (!server_ip) return res.json({ code: 400, message: '缺少 server_ip' });
  let inst = db.prepare('SELECT * FROM cloud_instance WHERE server_ip=? AND proxy_port=?').get(server_ip, proxy_port || 8901);
  if (!inst) {
    db.prepare('INSERT INTO cloud_instance (name, server_ip, proxy_port, status) VALUES (?,?,?,?)').run('auto-' + server_ip, server_ip, proxy_port || 8901, 'online');
    inst = db.prepare('SELECT * FROM cloud_instance WHERE server_ip=? AND proxy_port=?').get(server_ip, proxy_port || 8901);
  }
  db.prepare("UPDATE cloud_instance SET status='online', last_heartbeat=CURRENT_TIMESTAMP, active_sessions=?, cpu_usage=?, memory_usage=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
    .run(active_sessions || 0, cpu_usage || 0, memory_usage || 0, inst.id);
  if (sessions && Array.isArray(sessions)) {
    db.prepare("UPDATE cloud_session SET status='disconnected', disconnected_at=CURRENT_TIMESTAMP WHERE instance_id=? AND status='active'").run(inst.id);
    for (const s of sessions) {
      db.prepare("INSERT INTO cloud_session (instance_id, license_key, device_hash, client_ip, account_email, status, requests_count, connected_at) VALUES (?,?,?,?,?,?,?,CURRENT_TIMESTAMP)")
        .run(inst.id, s.license_key || '', s.device_hash || '', s.client_ip || '', s.account_email || '', 'active', s.requests_count || 0);
    }
  }
  res.json({ code: 0, message: 'ok' });
});

// ═══ Client API (mimics kc.szbjxbj.com) ═══

// Health
app.get('/api/health', (req, res) => {
  res.json({ code: 0, message: 'ok', timestamp: new Date().toISOString() });
});

// HMAC signature verification
function verifySign(req) {
  const ts = req.headers['x-kc-ts'];
  const nonce = req.headers['x-kc-nonce'];
  const sign = req.headers['x-kc-sign'];
  const device = req.headers['x-kc-device'];
  if (!ts || !nonce || !sign || !device) return { valid: false, reason: '缺少签名参数' };
  // Check timestamp (5 min window)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(ts)) > 300) return { valid: false, reason: '请求已过期' };
  // Check nonce replay
  const used = db.prepare('SELECT nonce FROM used_nonce WHERE nonce = ?').get(nonce);
  if (used) return { valid: false, reason: '重复请求' };
  // Store nonce
  db.prepare('INSERT OR IGNORE INTO used_nonce (nonce, ts) VALUES (?, ?)').run(nonce, parseInt(ts));
  const body = JSON.stringify(req.body || {});
  const expected = crypto.createHmac('sha256', SIGN_SECRET)
    .update(`${ts}:${nonce}:${device}:${body}`)
    .digest('hex');
  if (sign !== expected) return { valid: false, reason: '签名验证失败' };
  return { valid: true, device };
}

// Check device ban
function checkDeviceBan(device) {
  const banned = db.prepare("SELECT id FROM device_blacklist WHERE device_hash = ? AND status = 'active'").get(device);
  return !!banned;
}

// Enc-key endpoint (client calls this)
app.post('/api/enc-key', (req, res) => {
  const { build_id, bundle_hash } = req.body || {};
  // Check version
  const version = req.headers['x-kc-version'];
  if (version && version < '5.9.0') return res.status(403).json({ code: 403, message: `版本过低 (${version})，请升级到 5.9.0+`, action: 'kill', forceUpdate: true });

  const sigResult = verifySign(req);
  if (!sigResult.valid) return res.status(403).json({ code: 403, message: sigResult.reason });

  // Check device ban
  if (checkDeviceBan(sigResult.device)) {
    return res.status(403).json({ code: 403, message: '设备已被限制', action: 'kill' });
  }

  // Look up share
  const share = db.prepare('SELECT share FROM enc_key_share WHERE build_id = ?').get(build_id);
  if (share) return res.json({ code: 0, share: share.share });
  return res.status(404).json({ code: 404, message: 'share not found for this build' });
});

// ═══ Serve console frontend ═══
app.use('/console', (req, res, next) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
}, express.static(path.join(__dirname, 'public'), { maxAge: 0, etag: false, lastModified: false }));
app.get('/console/', (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══ Catch-all ═══
app.all('*', (req, res) => {
  res.status(404).json({ code: 404, message: 'endpoint not found' });
});

// ═══ Start ═══
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ KC-MCP Server running on port ${PORT}`);
  console.log(`   Admin panel: http://localhost:${PORT}/console/`);
  console.log(`   Admin API:   http://localhost:${PORT}/admin/`);
  console.log(`   Client API:  http://localhost:${PORT}/api/`);
});
