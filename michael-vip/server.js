const express = require('express');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const path = require('path');
const app = express();

// Behind Cloudflare the origin only ever sees a handful of CF edge IPs. Derive
// the REAL client IP from CF-Connecting-IP (which CF sets and clients cannot
// forge) so that rate limiting and audit logging key on the actual user. Without
// this, all users behind one CF edge share a single rate-limit bucket and get
// collectively throttled (429 → "许可证服务器连接异常").
app.set('trust proxy', true);
app.use((req, res, next) => {
  const cf = req.headers['cf-connecting-ip'];
  if (cf) req.headers['x-forwarded-for'] = cf; // makes req.ip resolve to the real client
  next();
});

app.use(express.json());

/* Cloudflare Business cache-control headers: static assets get long Edge TTL
 * (CF caches at 310+ PoPs globally), API responses get short browser + Edge
 * TTL for freshness. Handshake / status get 30s Edge cache so CF absorbs
 * thundering-herd spikes from thousands of simultaneous plugin boots. */
app.use((req, res, next) => {
  const p = req.path;
  if (p.startsWith('/dl/')) {
    res.set('Cache-Control', 'public, max-age=300, s-maxage=3600');
    res.set('CDN-Cache-Control', 'public, max-age=3600');
  } else if (p === '/api/handshake' || p === '/api/status') {
    res.set('Cache-Control', 'public, max-age=5, s-maxage=30');
    res.set('CDN-Cache-Control', 'public, max-age=30');
  } else if (p === '/api/update/check' || p === '/api/update/announcements') {
    res.set('Cache-Control', 'public, max-age=60, s-maxage=300');
    res.set('CDN-Cache-Control', 'public, max-age=300');
  } else if (p.startsWith('/api/admin')) {
    res.set('Cache-Control', 'no-store');
  } else if (p.startsWith('/api/license') || p.startsWith('/api/validate') ||
             p.startsWith('/api/activate') || p.startsWith('/api/heartbeat')) {
    res.set('Cache-Control', 'no-store');
  }
  next();
});

// Download tracking: log every /dl/* hit (real client IP via the CF middleware
// above) and bump the latest version's download_count, then hand off to static.
app.use('/dl', async (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') {
    (async () => {
      try {
        await ensureContentTables();
        const db = await getPool();
        const file = (req.path || '').replace(/^\//, '');
        const ua = String(req.headers['user-agent'] || '').slice(0, 500);
        const [vr] = await db.query("SELECT id, version FROM app_versions WHERE status='published' ORDER BY id DESC LIMIT 1");
        const ver = vr.length ? vr[0].version : '';
        await db.query('INSERT INTO download_logs (file, version, channel, ip, user_agent) VALUES (?,?,?,?,?)', [file, ver, 'vsix', req.ip, ua]);
        if (vr.length) await db.query('UPDATE app_versions SET download_count = download_count + 1 WHERE id = ?', [vr[0].id]);
      } catch (e) { /* best-effort; never block the download */ }
    })();
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Activation is a rare per-device action — key by real client IP (brute-force guard).
const activateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: { ok: false, error: '请求过于频繁，请稍后再试' },
  keyGenerator: (req) => req.ip,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false
});
// Validation is a frequent per-device heartbeat — key by machineId with a high
// ceiling so one device can never throttle another (the previous shared-IP
// limiter caused mass disconnects behind Cloudflare).
const validateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  message: { ok: false, error: '请求过于频繁，请稍后再试' },
  keyGenerator: (req) => (req.body && req.body.machineId) ? 'm:' + req.body.machineId : 'ip:' + req.ip,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false
});
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { ok: false, error: '管理接口请求过于频繁' },
  keyGenerator: (req) => req.ip,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false
});

const DB_CONFIG = {
  host: process.env.DB_HOST || '127.0.0.1',
  port: parseInt(process.env.DB_PORT || '3306'),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'michael_vip',
  socketPath: process.env.MYSQL_SOCKET || (process.platform === 'linux' ? '/var/run/mysqld/mysqld.sock' : `${process.env.HOME}/mysql/mysql.sock`)
};

if (!DB_CONFIG.password) {
  console.error('[FATAL] 必须设置环境变量 DB_PASSWORD');
  process.exit(1);
}

let pool;

async function getPool() {
  if (!pool) {
    pool = mysql.createPool({ ...DB_CONFIG, waitForConnections: true, connectionLimit: 10 });
  }
  return pool;
}

function generateKey(type = 'monthly') {
  const prefix = { trial: 'TRIAL', daily: 'DAY', monthly: 'MONTH', yearly: 'YEAR', lifetime: 'LIFE' }[type] || 'MONTH';
  const rand = crypto.randomBytes(8).toString('hex').toUpperCase();
  return `MVIP-${prefix}-${rand.slice(0, 4)}-${rand.slice(4, 8)}`;
}

// Shared content tables (versions + announcements) — single source of truth for
// the admin console (8900) AND the plugin-facing update/announcement endpoints.
let _contentTablesReady = false;
async function ensureContentTables() {
  if (_contentTablesReady) return;
  const db = await getPool();
  await db.query(`CREATE TABLE IF NOT EXISTS app_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    version VARCHAR(32) NOT NULL,
    changelog TEXT,
    download_url VARCHAR(512) DEFAULT '',
    force_update TINYINT(1) DEFAULT 0,
    channel VARCHAR(32) DEFAULT 'stable',
    status VARCHAR(16) DEFAULT 'published',
    download_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) DEFAULT CHARSET=utf8mb4`);
  await db.query(`CREATE TABLE IF NOT EXISTS app_announcements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) DEFAULT '',
    content TEXT,
    level VARCHAR(16) DEFAULT 'info',
    disabled TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) DEFAULT CHARSET=utf8mb4`);
  await db.query(`CREATE TABLE IF NOT EXISTS download_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file VARCHAR(255) DEFAULT '',
    version VARCHAR(32) DEFAULT '',
    channel VARCHAR(32) DEFAULT 'vsix',
    ip VARCHAR(64) DEFAULT '',
    user_agent VARCHAR(512) DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) DEFAULT CHARSET=utf8mb4`);
  _contentTablesReady = true;
}

// Numeric-aware version compare: returns true when client < latest.
function isClientOutdated(clientVer, latestVer) {
  if (!clientVer || !latestVer) return false;
  const a = String(clientVer).split('.').map(n => parseInt(n) || 0);
  const b = String(latestVer).split('.').map(n => parseInt(n) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] || 0, y = b[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

const SERVER_SECRET = process.env.SERVER_SECRET || '';
const ADMIN_KEY = process.env.ADMIN_KEY || '';

if (!SERVER_SECRET || !ADMIN_KEY) {
  console.error('[FATAL] 必须设置环境变量: SERVER_SECRET, ADMIN_KEY');
  process.exit(1);
}

function signResponse(data) {
  const payload = JSON.stringify(data);
  const sig = crypto.createHmac('sha256', SERVER_SECRET)
    .update(payload).digest('hex');
  return { ...data, sig };
}

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.post('/api/license/activate', activateLimiter, async (req, res) => {
  const { licenseKey, machineId, machineName } = req.body;
  if (!licenseKey || !machineId) {
    return res.status(400).json({ ok: false, error: '缺少 licenseKey 或 machineId' });
  }

  const db = await getPool();
  const conn = await db.getConnection();

  try {
    await conn.beginTransaction();

    const [keys] = await conn.query('SELECT * FROM license_keys WHERE license_key = ? FOR UPDATE', [licenseKey]);
    if (keys.length === 0) {
      await conn.rollback();
      await logAction(db, null, machineId, 'reject', req.ip, { reason: 'invalid_key' });
      return res.json(signResponse({ ok: false, error: '无效的卡密' }));
    }

    const key = keys[0];

    if (key.status === 'disabled') {
      await conn.rollback();
      return res.json(signResponse({ ok: false, error: '该卡密已被禁用' }));
    }
    if (key.status === 'expired') {
      await conn.rollback();
      return res.json(signResponse({ ok: false, error: '该卡密已过期' }));
    }

    const [existingBinding] = await conn.query(
      'SELECT * FROM device_bindings WHERE license_id = ? AND machine_id = ? AND is_active = 1', [key.id, machineId]
    );

    if (existingBinding.length > 0) {
      const binding = existingBinding[0];
      if (binding.expires_at && new Date(binding.expires_at) < new Date()) {
        await conn.query('UPDATE device_bindings SET is_active = 0 WHERE id = ?', [binding.id]);
        const [activeCount] = await conn.query(
          'SELECT COUNT(*) as cnt FROM device_bindings WHERE license_id = ? AND is_active = 1', [key.id]
        );
        if (activeCount[0].cnt === 0) {
          await conn.query('UPDATE license_keys SET status = "expired" WHERE id = ?', [key.id]);
        }
        await conn.commit();
        return res.json(signResponse({ ok: false, error: '许可证已过期，请续费' }));
      }

      await conn.query('UPDATE device_bindings SET last_heartbeat = NOW() WHERE id = ?', [binding.id]);
      await conn.commit();
      await logAction(db, key.id, machineId, 'validate', req.ip, { reactivation: true });

      return res.json(signResponse({
        ok: true,
        license: { type: key.key_type, expiresAt: binding.expires_at, maxDevices: key.max_devices },
        message: '设备已激活'
      }));
    }

    const [deviceCount] = await conn.query(
      'SELECT COUNT(*) as cnt FROM device_bindings WHERE license_id = ? AND is_active = 1', [key.id]
    );

    if (deviceCount[0].cnt >= key.max_devices) {
      await conn.rollback();
      await logAction(db, key.id, machineId, 'reject', req.ip, { reason: 'max_devices', current: deviceCount[0].cnt });
      return res.json(signResponse({ ok: false, error: `已达最大设备数 (${key.max_devices})` }));
    }

    const expiresAt = new Date();
    if (key.duration_days >= 36500) {
      expiresAt.setFullYear(2099, 11, 31);
    } else {
      expiresAt.setDate(expiresAt.getDate() + key.duration_days);
    }

    const [inactive] = await conn.query(
      'SELECT id FROM device_bindings WHERE license_id = ? AND machine_id = ? AND is_active = 0', [key.id, machineId]
    );
    if (inactive.length > 0) {
      await conn.query(
        'UPDATE device_bindings SET is_active = 1, expires_at = ?, last_heartbeat = NOW(), machine_name = ? WHERE id = ?',
        [expiresAt, machineName || '', inactive[0].id]
      );
    } else {
      await conn.query(
        'INSERT INTO device_bindings (license_id, machine_id, machine_name, expires_at, last_heartbeat) VALUES (?, ?, ?, ?, NOW())',
        [key.id, machineId, machineName || '', expiresAt]
      );
    }

    if (key.status === 'unused') {
      await conn.query('UPDATE license_keys SET status = "active" WHERE id = ?', [key.id]);
    }

    await conn.commit();
    await logAction(db, key.id, machineId, 'activate', req.ip, { machineName, expiresAt });

    res.json(signResponse({
      ok: true,
      license: { type: key.key_type, expiresAt: expiresAt.toISOString(), maxDevices: key.max_devices },
      message: '激活成功'
    }));
  } catch (err) {
    await conn.rollback();
    console.error('[Activate Error]', err.message);
    res.status(500).json({ ok: false, error: '服务器内部错误' });
  } finally {
    conn.release();
  }
});

const handleLicenseValidate = async (req, res) => {
  const { licenseKey, machineId } = req.body;
  if (!licenseKey || !machineId) {
    return res.status(400).json({ ok: false, error: '缺少参数' });
  }

  const db = await getPool();

  try {
    const [rows] = await db.query(`
      SELECT k.*, b.expires_at, b.is_active, b.last_heartbeat
      FROM license_keys k
      JOIN device_bindings b ON b.license_id = k.id
      WHERE k.license_key = ? AND b.machine_id = ? AND b.is_active = 1
    `, [licenseKey, machineId]);

    if (rows.length === 0) {
      return res.json(signResponse({ ok: false, valid: false, error: '未找到有效绑定' }));
    }

    const row = rows[0];

    if (row.status === 'disabled') {
      return res.json(signResponse({ ok: false, valid: false, error: '许可证已禁用' }));
    }

    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      return res.json(signResponse({ ok: true, valid: false, error: '许可证已过期', expired: true }));
    }

    await db.query(
      'UPDATE device_bindings SET last_heartbeat = NOW() WHERE license_id = ? AND machine_id = ?',
      [row.id, machineId]
    );

    res.json(signResponse({
      ok: true,
      valid: true,
      license: {
        type: row.key_type,
        expiresAt: row.expires_at,
        maxDevices: row.max_devices,
        status: row.status
      }
    }));
  } catch (err) {
    console.error('[Validate Error]', err.message);
    res.status(500).json({ ok: false, error: '服务器内部错误' });
  }
};
// /api/license/verify is an alias of validate (older plugin builds call verify).
app.post('/api/license/validate', validateLimiter, handleLicenseValidate);
app.post('/api/license/verify', activateLimiter, handleLicenseValidate);

app.post('/api/license/deactivate', async (req, res) => {
  const { licenseKey, machineId } = req.body;
  if (!licenseKey || !machineId) {
    return res.status(400).json({ ok: false, error: '缺少参数' });
  }

  const db = await getPool();

  try {
    const [keys] = await db.query('SELECT id FROM license_keys WHERE license_key = ?', [licenseKey]);
    if (keys.length === 0) {
      return res.json(signResponse({ ok: false, error: '无效的卡密' }));
    }

    const [result] = await db.query(
      'UPDATE device_bindings SET is_active = 0 WHERE license_id = ? AND machine_id = ?',
      [keys[0].id, machineId]
    );

    await logAction(db, keys[0].id, machineId, 'deactivate', req.ip, {});

    res.json(signResponse({ ok: true, message: '已解绑设备', affected: result.affectedRows }));
  } catch (err) {
    console.error('[Deactivate Error]', err.message);
    res.status(500).json({ ok: false, error: '服务器内部错误' });
  }
});

app.post('/api/admin/generate', adminLimiter, async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ ok: false, error: '无权限' });
  }

  const { type = 'monthly', count = 1, maxDevices = 1, durationDays } = req.body;
  const durations = { trial: 7, daily: 1, monthly: 30, yearly: 365, lifetime: 99999 };
  const duration = durationDays || durations[type] || 30;

  const db = await getPool();
  const keys = [];

  for (let i = 0; i < Math.min(count, 100); i++) {
    const key = generateKey(type);
    await db.query(
      'INSERT INTO license_keys (license_key, key_type, max_devices, duration_days) VALUES (?, ?, ?, ?)',
      [key, type, maxDevices, duration]
    );
    keys.push(key);
  }

  res.json(signResponse({ ok: true, keys, type, maxDevices, durationDays: duration }));
});

app.get('/api/admin/stats', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ ok: false, error: '无权限' });
  }

  const db = await getPool();

  const [total] = await db.query('SELECT COUNT(*) as cnt FROM license_keys');
  const [byStatus] = await db.query('SELECT status, COUNT(*) as cnt FROM license_keys GROUP BY status');
  const [byType] = await db.query('SELECT key_type, COUNT(*) as cnt FROM license_keys GROUP BY key_type');
  const [activeDevices] = await db.query('SELECT COUNT(*) as cnt FROM device_bindings WHERE is_active = 1');
  const [recentLogs] = await db.query('SELECT action, COUNT(*) as cnt FROM activation_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY action');

  res.json(signResponse({
    ok: true,
    totalKeys: total[0].cnt,
    byStatus: Object.fromEntries(byStatus.map(r => [r.status, r.cnt])),
    byType: Object.fromEntries(byType.map(r => [r.key_type, r.cnt])),
    activeDevices: activeDevices[0].cnt,
    last24hActions: Object.fromEntries(recentLogs.map(r => [r.action, r.cnt]))
  }));
});

app.get('/api/admin/keys', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ ok: false, error: '无权限' });
  }
  const { status, type, search, page = 1, limit = 50 } = req.query;
  const db = await getPool();
  try {
    let where = '1=1';
    const params = [];
    if (status) { where += ' AND k.status = ?'; params.push(status); }
    if (type) { where += ' AND k.key_type = ?'; params.push(type); }
    if (search) {
      where += ' AND (k.license_key LIKE ? OR k.id IN (SELECT license_id FROM device_bindings WHERE machine_name LIKE ? OR machine_id LIKE ?))';
      const s = `%${search}%`;
      params.push(s, s, s);
    }
    const offset = (Math.max(1, parseInt(page)) - 1) * parseInt(limit);
    const [countResult] = await db.query(`SELECT COUNT(*) as total FROM license_keys k WHERE ${where}`, params);
    const [rows] = await db.query(`
      SELECT k.*,
        (SELECT COUNT(*) FROM device_bindings WHERE license_id = k.id AND is_active = 1) as active_devices,
        (SELECT GROUP_CONCAT(machine_name SEPARATOR ', ') FROM device_bindings WHERE license_id = k.id AND is_active = 1) as device_names
      FROM license_keys k WHERE ${where} ORDER BY k.id DESC LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), offset]);
    res.json({ ok: true, total: countResult[0].total, page: parseInt(page), limit: parseInt(limit), keys: rows });
  } catch (err) {
    console.error('[Keys List Error]', err.message);
    res.status(500).json({ ok: false, error: '查询失败' });
  }
});

app.put('/api/admin/keys/:id/status', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ ok: false, error: '无权限' });
  }
  const { id } = req.params;
  const { status } = req.body;
  if (!['unused', 'active', 'expired', 'disabled'].includes(status)) {
    return res.status(400).json({ ok: false, error: '无效状态' });
  }
  const db = await getPool();
  try {
    await db.query('UPDATE license_keys SET status = ? WHERE id = ?', [status, id]);
    res.json(signResponse({ ok: true, message: '状态已更新' }));
  } catch (err) {
    console.error('[Key Status Error]', err.message);
    res.status(500).json({ ok: false, error: '更新失败' });
  }
});

app.patch('/api/admin/keys/:id', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const { status, maxDevices } = req.body;
  const db = await getPool();
  const updates = [], params = [];
  if (status) { updates.push('status = ?'); params.push(status); }
  if (maxDevices !== undefined) { updates.push('max_devices = ?'); params.push(maxDevices); }
  if (updates.length === 0) return res.json({ ok: false, error: '无更新内容' });
  params.push(req.params.id);
  await db.query(`UPDATE license_keys SET ${updates.join(', ')} WHERE id = ?`, params);
  res.json({ ok: true });
});

app.get('/api/admin/keys/:id', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const db = await getPool();
  const [keys] = await db.query('SELECT * FROM license_keys WHERE id = ?', [req.params.id]);
  if (keys.length === 0) return res.json({ ok: false, error: '未找到' });
  const [bindings] = await db.query('SELECT * FROM device_bindings WHERE license_id = ? ORDER BY is_active DESC, activated_at DESC', [req.params.id]);
  const [logs] = await db.query('SELECT * FROM activation_logs WHERE license_id = ? ORDER BY created_at DESC LIMIT 20', [req.params.id]);
  res.json({ ok: true, key: keys[0], bindings, logs });
});

app.post('/api/admin/keys/:id/ban', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const db = await getPool();
  try {
    await db.query('UPDATE license_keys SET status = "disabled" WHERE id = ?', [req.params.id]);
    const [result] = await db.query('UPDATE device_bindings SET is_active = 0 WHERE license_id = ?', [req.params.id]);
    await logAction(db, parseInt(req.params.id), null, 'reject', req.ip, { action: 'ban', devicesUnbound: result.affectedRows });
    res.json({ ok: true, devicesUnbound: result.affectedRows });
  } catch (err) {
    res.status(500).json({ ok: false, error: '操作失败' });
  }
});

app.delete('/api/admin/keys/:id', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const db = await getPool();
  await db.query('UPDATE device_bindings SET is_active = 0 WHERE license_id = ?', [req.params.id]);
  await db.query('DELETE FROM license_keys WHERE id = ?', [req.params.id]);
  await logAction(db, parseInt(req.params.id), null, 'reject', req.ip, { action: 'delete' });
  res.json({ ok: true });
});

app.delete('/api/admin/bindings/:id', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const db = await getPool();
  await db.query('UPDATE device_bindings SET is_active = 0 WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/admin/logs', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const { page = 1, limit = 50 } = req.query;
  const db = await getPool();
  const offset = (Math.max(1, parseInt(page)) - 1) * parseInt(limit);
  const [total] = await db.query('SELECT COUNT(*) as cnt FROM activation_logs');
  const [rows] = await db.query(`
    SELECT l.*, k.license_key FROM activation_logs l
    LEFT JOIN license_keys k ON k.id = l.license_id
    ORDER BY l.created_at DESC LIMIT ? OFFSET ?
  `, [parseInt(limit), offset]);
  res.json({ ok: true, total: total[0].cnt, logs: rows });
});

app.get('/api/admin/bindings', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ ok: false, error: '无权限' });
  }
  const db = await getPool();
  try {
    const [bindings] = await db.query(`
      SELECT b.*, k.license_key
      FROM device_bindings b
      JOIN license_keys k ON k.id = b.license_id
      ORDER BY b.activated_at DESC
    `);
    res.json(signResponse({ ok: true, bindings }));
  } catch (err) {
    console.error('[Bindings List Error]', err.message);
    res.status(500).json({ ok: false, error: '查询失败' });
  }
});

async function logAction(db, licenseId, machineId, action, ip, details) {
  try {
    await db.query(
      'INSERT INTO activation_logs (license_id, machine_id, action, ip_address, details) VALUES (?, ?, ?, ?, ?)',
      [licenseId, machineId, action, ip, JSON.stringify(details)]
    );
  } catch (err) {
    console.error('[Log Error]', err.message);
  }
}

/* === Original KCChat API Compatibility Layer === */

/* === enc-key removed — not needed, instant bypass in plugin === */
const fs = require('fs');
const https = require('https');
app.post('/api/enc-key', (req, res) => res.json({ ok: false, share: '' }));
app.post('/api/enc-key/cache', (req, res) => res.json({ ok: true }));
app.post('/api/enc-key/proxy', (req, res) => res.json({ ok: false, share: '' }));

app.post('/api/validate', async (req, res) => {
  const { machineId, licenseKey } = req.body || {};
  if (!machineId || !licenseKey) {
    return res.json({ ok: true, valid: false, tier: 'free', error: 'missing_params' });
  }
  try {
    const db = await getPool();
    const [rows] = await db.query(
      `SELECT b.*, k.key_type, k.status as key_status FROM device_bindings b
       JOIN license_keys k ON k.id = b.license_id
       WHERE k.license_key = ? AND b.machine_id = ? AND b.is_active = 1 AND k.status NOT IN ('disabled', 'expired')
       ORDER BY b.expires_at DESC LIMIT 1`, [licenseKey, machineId]);
    if (rows.length > 0) {
      const r = rows[0];
      if (r.expires_at && new Date(r.expires_at) < new Date()) {
        return res.json({ ok: true, valid: false, expired: true, tier: 'free' });
      }
      await db.query('UPDATE device_bindings SET last_heartbeat = NOW() WHERE id = ?', [r.id]);
      return res.json({ ok: true, valid: true, tier: 'pro', features: ['all'] });
    }
  } catch (e) { console.error('[compat/validate]', e.message); }
  res.json({ ok: true, valid: false, tier: 'free', error: 'no_active_binding' });
});

app.post('/api/activate', async (req, res) => {
  const { machineId, licenseKey, machineName } = req.body || {};
  if (!machineId || !licenseKey) {
    return res.json({ ok: false, activated: false, error: 'missing_params' });
  }
  try {
    const db = await getPool();
    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();
      const [keys] = await conn.query('SELECT * FROM license_keys WHERE license_key = ? AND status NOT IN (?, ?) FOR UPDATE', [licenseKey, 'disabled', 'expired']);
      if (keys.length === 0) {
        await conn.rollback();
        await logAction(db, null, machineId, 'reject', req.ip, { reason: 'invalid_key', via: 'compat' });
        return res.json({ ok: false, activated: false, error: 'invalid_key' });
      }
      const key = keys[0];
      const [existing] = await conn.query(
        'SELECT * FROM device_bindings WHERE license_id = ? AND machine_id = ? AND is_active = 1', [key.id, machineId]
      );
      if (existing.length > 0) {
        const b = existing[0];
        if (b.expires_at && new Date(b.expires_at) < new Date()) {
          await conn.query('UPDATE device_bindings SET is_active = 0 WHERE id = ?', [b.id]);
          await conn.rollback();
          return res.json({ ok: false, activated: false, error: 'expired' });
        }
        await conn.query('UPDATE device_bindings SET last_heartbeat = NOW() WHERE id = ?', [b.id]);
        await conn.commit();
        return res.json({ ok: true, activated: true, tier: 'pro' });
      }
      const [devCnt] = await conn.query('SELECT COUNT(*) as cnt FROM device_bindings WHERE license_id = ? AND is_active = 1', [key.id]);
      if (devCnt[0].cnt >= key.max_devices) {
        await conn.rollback();
        return res.json({ ok: false, activated: false, error: 'max_devices_reached' });
      }
      const expiresAt = new Date();
      if (key.duration_days >= 36500) expiresAt.setFullYear(2099, 11, 31);
      else expiresAt.setDate(expiresAt.getDate() + key.duration_days);
      const [inactiveCompat] = await conn.query(
        'SELECT id FROM device_bindings WHERE license_id = ? AND machine_id = ? AND is_active = 0', [key.id, machineId]
      );
      if (inactiveCompat.length > 0) {
        await conn.query(
          'UPDATE device_bindings SET is_active = 1, expires_at = ?, last_heartbeat = NOW(), machine_name = ? WHERE id = ?',
          [expiresAt, machineName || '', inactiveCompat[0].id]
        );
      } else {
        await conn.query(
          'INSERT INTO device_bindings (license_id, machine_id, machine_name, expires_at, last_heartbeat) VALUES (?, ?, ?, ?, NOW())',
          [key.id, machineId, machineName || '', expiresAt]
        );
      }
      if (key.status === 'unused') await conn.query('UPDATE license_keys SET status = "active" WHERE id = ?', [key.id]);
      await conn.commit();
      await logAction(db, key.id, machineId, 'activate', req.ip, { machineName, via: 'compat' });
      return res.json({ ok: true, activated: true, tier: 'pro' });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally { conn.release(); }
  } catch (e) { console.error('[compat/activate]', e.message); }
  res.json({ ok: false, activated: false, error: 'server_error' });
});

app.post('/api/heartbeat', async (req, res) => {
  const { machineId } = req.body || {};
  if (machineId) {
    try {
      const db = await getPool();
      await db.query('UPDATE device_bindings SET last_heartbeat = NOW() WHERE machine_id = ? AND is_active = 1', [machineId]);
    } catch (e) {}
  }
  res.json({ ok: true });
});

app.post('/api/check', async (req, res) => {
  const { machineId, licenseKey } = req.body || {};
  if (!machineId) {
    return res.json({ ok: true, valid: false, status: 'inactive', tier: 'free' });
  }
  try {
    const db = await getPool();
    let query, params;
    if (licenseKey) {
      query = `SELECT b.*, k.key_type FROM device_bindings b
        JOIN license_keys k ON k.id = b.license_id
        WHERE k.license_key = ? AND b.machine_id = ? AND b.is_active = 1 AND k.status NOT IN ('disabled')
        ORDER BY b.expires_at DESC LIMIT 1`;
      params = [licenseKey, machineId];
    } else {
      query = `SELECT b.*, k.key_type FROM device_bindings b
        JOIN license_keys k ON k.id = b.license_id
        WHERE b.machine_id = ? AND b.is_active = 1 AND k.status NOT IN ('disabled')
        ORDER BY b.expires_at DESC LIMIT 1`;
      params = [machineId];
    }
    const [rows] = await db.query(query, params);
    if (rows.length > 0) {
      const r = rows[0];
      if (r.expires_at && new Date(r.expires_at) < new Date()) {
        return res.json({ ok: true, valid: false, status: 'expired', tier: 'free' });
      }
      return res.json({ ok: true, valid: true, status: 'active', tier: 'pro' });
    }
  } catch (e) { console.error('[compat/check]', e.message); }
  res.json({ ok: true, valid: false, status: 'inactive', tier: 'free' });
});

app.get('/api/status', (req, res) => {
  res.json({ ok: true, status: 'online', version: '6.3.3' });
});

app.get('/api/cf-health', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    ok: true, ts: Date.now(),
    cf: {
      ray: req.headers['cf-ray'] || null,
      colo: req.headers['cf-ipcountry'] || null,
      connecting_ip: req.headers['cf-connecting-ip'] || req.ip,
    }
  });
});

/* === WebSocket Relay for Remote Collaboration (Room-based, multi-party) === */
const WebSocket = require('ws');

// code -> Room { code, ownerId, createdAt, hostInfo, participants: Map<id, {ws,id,name,color,role,presence}> }
const relayRooms = new Map();
const RELAY_SESSION_TTL = 5 * 60 * 1000;
const RELAY_MAX_TTL = 4 * 60 * 60 * 1000;
const RELAY_MAX_PARTICIPANTS = parseInt(process.env.RELAY_MAX_PARTICIPANTS || '30');
const RELAY_MAX_MSG_SIZE = 2 * 1024 * 1024; // 2 MB
const RELAY_RATE_LIMIT = 60; // max messages per second per connection
const _relayMsgCounts = new WeakMap();

function relaySend(ws, msg) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(msg)); } catch(e) {}
  }
}

function roomRoster(room) {
  const list = [];
  room.participants.forEach(p => {
    list.push({ id: p.id, name: p.name, color: p.color, role: p.role, presence: p.presence || null, avatar: p.avatar || '' });
  });
  return list;
}

function broadcastRoster(room) {
  const msg = { type: 'room:roster', ts: Date.now(), payload: { code: room.code, ownerId: room.ownerId, participants: roomRoster(room) } };
  room.participants.forEach(p => relaySend(p.ws, msg));
}

function broadcastToRoom(room, msg, exceptId) {
  room.participants.forEach(p => {
    if (exceptId && p.id === exceptId) return;
    relaySend(p.ws, msg);
  });
}

function handleRelayMessage(ws, msg) {
  const type = msg.type;
  const from = msg.from || {};

  switch(type) {
    case 'room:create':
    case 'session:create': { // session:create kept for backward compat
      const code = msg.payload && msg.payload.code;
      if (!code || relayRooms.has(code)) {
        relaySend(ws, { type: 'error', payload: { message: 'invalid or duplicate room code' } });
        return;
      }
      const room = {
        code, ownerId: from.id, createdAt: Date.now(),
        hostInfo: msg.payload.hostInfo || {}, participants: new Map()
      };
      room.participants.set(from.id, {
        ws, id: from.id, name: from.name || 'Owner', color: from.color || '#8b5cf6',
        role: 'owner', presence: null, avatar: from.avatar || ''
      });
      relayRooms.set(code, room);
      ws._roomCode = code; ws._pid = from.id;
      relaySend(ws, { type: 'room:created', payload: { code, you: { id: from.id, role: 'owner' } } });
      broadcastRoster(room);
      console.log(`[Relay] Room created: ${code} by ${from.name || from.id}`);
      break;
    }
    case 'room:join':
    case 'session:join': { // session:join kept for backward compat
      const code = msg.payload && msg.payload.code;
      const room = relayRooms.get(code);
      if (!room) {
        relaySend(ws, { type: 'error', payload: { message: 'room not found' } });
        return;
      }
      if (room.participants.size >= RELAY_MAX_PARTICIPANTS) {
        relaySend(ws, { type: 'error', payload: { message: '房间已满（最多 ' + RELAY_MAX_PARTICIPANTS + ' 人）' } });
        return;
      }
      ws._roomCode = code; ws._pid = from.id;
      // Auto-join as viewer (read-only). Owner promotes to editor.
      room.participants.set(from.id, {
        ws, id: from.id, name: from.name || 'Guest', color: from.color || '#60a5fa',
        role: 'viewer', presence: null, avatar: from.avatar || ''
      });
      relaySend(ws, { type: 'room:joined', payload: { code, you: { id: from.id, role: 'viewer' }, ownerId: room.ownerId, hostInfo: room.hostInfo } });
      broadcastToRoom(room, { type: 'room:participant-joined', from, ts: Date.now(), payload: {} }, from.id);
      broadcastRoster(room);
      console.log(`[Relay] ${from.name || from.id} joined room ${code}`);
      break;
    }
    case 'room:role': { // owner changes a participant's role
      const room = relayRooms.get(ws._roomCode);
      if (!room || ws._pid !== room.ownerId) return;
      const targetId = msg.payload && msg.payload.targetId;
      const role = msg.payload && msg.payload.role;
      const target = room.participants.get(targetId);
      if (target && (role === 'editor' || role === 'viewer')) {
        target.role = role;
        relaySend(target.ws, { type: 'room:your-role', payload: { role } });
        broadcastRoster(room);
        console.log(`[Relay] Role: ${targetId} -> ${role} in ${room.code}`);
      }
      break;
    }
    case 'room:kick': { // owner removes a participant
      const room = relayRooms.get(ws._roomCode);
      if (!room || ws._pid !== room.ownerId) return;
      const targetId = msg.payload && msg.payload.targetId;
      const target = room.participants.get(targetId);
      if (target && targetId !== room.ownerId) {
        relaySend(target.ws, { type: 'room:kicked', payload: {} });
        room.participants.delete(targetId);
        target.ws._roomCode = null;
        broadcastRoster(room);
      }
      break;
    }
    case 'presence:update': {
      const room = relayRooms.get(ws._roomCode);
      if (!room) return;
      const p = room.participants.get(ws._pid);
      if (p) p.presence = msg.payload || null;
      broadcastToRoom(room, { type: 'presence:update', from, ts: Date.now(), payload: msg.payload }, ws._pid);
      break;
    }
    case 'ping': break;
    default: {
      // Generic routing: targeted via payload.to, else broadcast to all except sender
      const room = relayRooms.get(ws._roomCode);
      if (!room) return;
      const to = msg.payload && msg.payload.to;
      if (to) {
        const target = room.participants.get(to);
        if (target) relaySend(target.ws, msg);
      } else {
        broadcastToRoom(room, msg, ws._pid);
      }
      break;
    }
  }
}

function handleRelayDisconnect(ws) {
  if (!ws._roomCode) return;
  const room = relayRooms.get(ws._roomCode);
  if (!room) return;
  const pid = ws._pid;
  const wasOwner = pid === room.ownerId;
  room.participants.delete(pid);
  if (wasOwner) {
    broadcastToRoom(room, { type: 'room:ended', from: { id: pid }, ts: Date.now(), payload: { reason: 'owner disconnected' } });
    room.participants.forEach(p => { p.ws._roomCode = null; });
    relayRooms.delete(room.code);
    console.log(`[Relay] Room ended (owner left): ${room.code}`);
  } else {
    broadcastToRoom(room, { type: 'room:participant-left', from: { id: pid }, ts: Date.now(), payload: {} });
    broadcastRoster(room);
    console.log(`[Relay] Participant left: ${pid} from ${room.code}`);
  }
  ws._roomCode = null;
}

// Relay stats endpoint
app.get('/api/relay/stats', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const rooms = [];
  relayRooms.forEach((r, code) => {
    rooms.push({ code, participants: r.participants.size, age: Math.round((Date.now() - r.createdAt) / 1000) + 's' });
  });
  res.json({ ok: true, activeRooms: relayRooms.size, rooms });
});

// Generate WebSocket relay auth token
app.post('/api/relay/token', activateLimiter, (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.json({ ok: false, error: 'missing id' });
  const ts = Date.now();
  const sig = crypto.createHmac('sha256', SERVER_SECRET)
    .update(`${id}:${ts}`).digest('hex').slice(0, 16);
  const token = Buffer.from(JSON.stringify({ id, ts, sig })).toString('base64url');
  res.json({ ok: true, token, expiresIn: 300 });
});

/* === KC Chat self-hosted backend (no upstream dependency) === */
const KC_UPSTREAM = 'kc.szbjxbj.com';

app.post('/api/handshake', (req, res) => {
  res.json({ code: 0, data: { status: 'active', server: 'michael-vip', ts: Date.now() } });
});

const DEFAULT_DOWNLOAD_URL = process.env.VSIX_DOWNLOAD_URL || 'https://api.michaelcursor.xyz/dl/michael-cursor-vip.vsix';

// Plugin-facing: latest published version. Returns the exact shape the client
// reads (resp.data.{hasUpdate,latestVersion,changelog,forceUpdate,channel}).
app.all('/api/update/check', async (req, res) => {
  try {
    await ensureContentTables();
    const db = await getPool();
    const [rows] = await db.query("SELECT * FROM app_versions WHERE status='published' ORDER BY id DESC LIMIT 1");
    const clientVer = req.query.v || (req.body && req.body.version) || '';
    if (!rows.length) return res.json({ code: 0, data: { hasUpdate: false, latestVersion: '', channel: 'stable' } });
    const v = rows[0];
    res.json({ code: 0, data: {
      hasUpdate: isClientOutdated(clientVer, v.version),
      latestVersion: v.version,
      changelog: v.changelog || '',
      downloadUrl: v.download_url || DEFAULT_DOWNLOAD_URL,
      forceUpdate: !!v.force_update,
      channel: v.channel || 'stable'
    }});
  } catch (e) {
    res.json({ code: 0, data: { hasUpdate: false, latestVersion: '', channel: 'stable', error: e.message } });
  }
});

app.all('/api/update/announcements', async (req, res) => {
  try {
    await ensureContentTables();
    const db = await getPool();
    const [rows] = await db.query("SELECT id, title, content, level, created_at FROM app_announcements WHERE disabled=0 ORDER BY id DESC LIMIT 50");
    const list = rows.map(a => ({ id: a.id, title: a.title || '', message: a.content || '', level: a.level || 'info', createdAt: a.created_at }));
    res.json({ code: 0, list, total: list.length });
  } catch (e) {
    res.json({ code: 0, list: [], total: 0, error: e.message });
  }
});

// Admin write endpoints (ADMIN_KEY); the 8900 console writes to the same tables.
app.post('/api/admin/announcement/create', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const { title, message, level } = req.body || {};
  if (!message) return res.json({ ok: false, error: 'message required' });
  try {
    await ensureContentTables();
    const db = await getPool();
    const [r] = await db.query('INSERT INTO app_announcements (title, content, level) VALUES (?,?,?)', [title || '', message, level || 'info']);
    res.json({ ok: true, id: r.insertId });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/admin/announcement/delete', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const { id } = req.body || {};
  try {
    await ensureContentTables();
    const db = await getPool();
    await db.query('UPDATE app_announcements SET disabled=1 WHERE id=?', [id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.get('/api/admin/announcements', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  try {
    await ensureContentTables();
    const db = await getPool();
    const [rows] = await db.query('SELECT * FROM app_announcements ORDER BY id DESC LIMIT 100');
    res.json({ ok: true, announcements: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/admin/version/set', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  const { version, changelog, downloadUrl, forceUpdate, channel } = req.body || {};
  if (!version) return res.json({ ok: false, error: 'version required' });
  try {
    await ensureContentTables();
    const db = await getPool();
    const [r] = await db.query('INSERT INTO app_versions (version, changelog, download_url, force_update, channel) VALUES (?,?,?,?,?)',
      [version, changelog || '', downloadUrl || DEFAULT_DOWNLOAD_URL, forceUpdate ? 1 : 0, channel || 'stable']);
    res.json({ ok: true, id: r.insertId });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.get('/api/admin/version', async (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  try {
    await ensureContentTables();
    const db = await getPool();
    const [rows] = await db.query("SELECT * FROM app_versions WHERE status='published' ORDER BY id DESC LIMIT 1");
    res.json({ ok: true, latestVersion: rows[0] || null });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.get('/api/admin/dashboard', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ ok: false, error: '无权限' });
  res.json({
    ok: true,
    version: _latestVersion.version,
    announcements: _announcements.filter(a => !a.disabled).length,
    activeRooms: relayRooms.size,
    uptime: Math.round(process.uptime()),
    memory: Math.round(process.memoryUsage().rss / 1048576) + 'MB',
    serverTime: new Date().toISOString()
  });
});

app.post('/api/license/install-id/check', (req, res) => {
  res.json({ code: 0, data: { valid: true, server: 'michael-vip' } });
});

/* Anti-tamper patch system: the plugin reports an install-id to revoke
   (fire-and-forget; the client logs "remote revoke failed" when this 404s).
   Always acknowledge so the client stays quiet, and record a best-effort
   audit entry whenever the license/device can be resolved. */
app.post('/api/license/install-id/revoke', async (req, res) => {
  const { install_id, source, reason, patch_version, license_key, machine_id } = req.body || {};
  try {
    console.log(`[install-id/revoke] iid=${String(install_id || '').slice(0, 8)} src=${source || ''} pv=${patch_version || ''} reason=${String(reason || '').slice(0, 120)}`);
    if (license_key && machine_id) {
      const db = await getPool();
      const [keys] = await db.query('SELECT id FROM license_keys WHERE license_key = ?', [license_key]);
      if (keys.length) {
        await logAction(db, keys[0].id, machine_id, 'install_id_revoke', req.ip, {
          install_id, source, reason: String(reason || '').slice(0, 200), patch_version
        });
      }
    }
  } catch (e) {
    console.error('[install-id/revoke Error]', e.message);
  }
  res.json({ code: 0, success: true, data: { revoked: true, server: 'michael-vip' } });
});

/* Patch-recipe: _core.js calls this before applying the base patch to
   workbench.desktop.main.js. The upstream server validates the license and
   returns install credentials; we always approve and mint a fresh installId
   so the core proceeds with patching regardless of Cursor version. */
app.post('/api/security/patch-recipe', (req, res) => {
  const installId = crypto.randomBytes(8).toString('hex');
  const installSecret = crypto.randomBytes(32).toString('base64');
  res.json({
    code: 0,
    data: {
      ok: true,
      action: 'apply',
      installId,
      installSecret,
      patchVersion: 'v8.8.0',
      server: 'michael-vip',
      ts: Date.now()
    }
  });
});

/* Patch sync: core reports patch status after applying. Always acknowledge. */
app.post('/api/security/patch-sync', (req, res) => {
  res.json({ code: 0, data: { ok: true, synced: true, server: 'michael-vip' } });
});

/* Patch heartbeat: core sends periodic heartbeats to verify patch is alive. */
app.post('/api/security/patch-heartbeat', (req, res) => {
  res.json({ code: 0, data: { ok: true, alive: true, server: 'michael-vip' } });
});

app.all('/api/*', (req, res) => {
  res.status(404).json({ ok: false, error: 'endpoint_not_found' });
});

// Cleanup expired rooms
setInterval(() => {
  const now = Date.now();
  relayRooms.forEach((room, code) => {
    if (now - room.createdAt > RELAY_MAX_TTL) {
      room.participants.forEach(p => { try { p.ws.close(1000); } catch(e) {} });
      relayRooms.delete(code);
    } else if (room.participants.size === 0 && now - room.createdAt > RELAY_SESSION_TTL) {
      relayRooms.delete(code);
    }
  });
}, 60000);

const PORT = parseInt(process.env.PORT || '3900');
const SSL_PORT = parseInt(process.env.SSL_PORT || '443');
const SSL_CERT = process.env.SSL_CERT || (fs.existsSync(path.join(__dirname, 'server.cert')) ? path.join(__dirname, 'server.cert') : '');
const SSL_KEY = process.env.SSL_KEY || (fs.existsSync(path.join(__dirname, 'server.key')) ? path.join(__dirname, 'server.key') : '');
const SSL_CA = process.env.SSL_CA || '';

const http = require('http');
const httpServer = http.createServer(app);

function setupWss(server) {
  const wss = new WebSocket.Server({
    server, path: '/ws/relay', maxPayload: RELAY_MAX_MSG_SIZE,
    verifyClient: (info, cb) => {
      const url = new URL(info.req.url, 'ws://localhost');
      const token = url.searchParams.get('token');
      if (!token) {
        cb(false, 401, 'Missing auth token');
        return;
      }
      try {
        const payload = JSON.parse(Buffer.from(token, 'base64url').toString());
        const ts = payload.ts || 0;
        if (Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
          cb(false, 401, 'Token expired');
          return;
        }
        const expectedSig = crypto.createHmac('sha256', SERVER_SECRET)
          .update(`${payload.id}:${ts}`).digest('hex').slice(0, 16);
        if (payload.sig !== expectedSig) {
          cb(false, 401, 'Invalid token signature');
          return;
        }
        info.req._verifiedId = payload.id;
        cb(true);
      } catch (e) {
        cb(false, 401, 'Invalid token format');
      }
    }
  });
  wss.on('connection', (ws, req) => {
    ws._roomCode = null;
    ws._pid = req._verifiedId || null;
    _relayMsgCounts.set(ws, { count: 0, resetAt: Date.now() + 1000 });
    ws.on('message', (raw) => {
      const rawStr = raw.toString();
      if (rawStr.length > RELAY_MAX_MSG_SIZE) { ws.close(1009, 'Message too large'); return; }
      const rl = _relayMsgCounts.get(ws);
      if (rl) {
        const now = Date.now();
        if (now > rl.resetAt) { rl.count = 0; rl.resetAt = now + 1000; }
        rl.count++;
        if (rl.count > RELAY_RATE_LIMIT) { ws.close(1008, 'Rate limit exceeded'); return; }
      }
      try { handleRelayMessage(ws, JSON.parse(rawStr)); } catch(e) {}
    });
    ws.on('close', () => handleRelayDisconnect(ws));
    ws.on('error', () => handleRelayDisconnect(ws));
  });
  return wss;
}

setupWss(httpServer);

/* === HTTP Relay Proxy for Cursor API (replaces CONNECT tunnel) === */
/* CONNECT tunnels don't work through Cloudflare free plan.
   This relay receives standard HTTPS POST requests and forwards them to Cursor API. */
const RELAY_ALLOWED_HOSTS = new Set([
  'api2.cursor.sh', 'api.cursor.com', 'cursor.sh',
  'api.cursor.sh', 'repo42.cursor.sh', 'marketplace.cursorapi.com'
]);
const net = require('net');

app.all('/api/cursor-relay/:targetHost/*', (req, res) => {
  const targetHost = req.params.targetHost;
  if (!RELAY_ALLOWED_HOSTS.has(targetHost)) {
    return res.status(403).json({ ok: false, error: 'host not allowed' });
  }
  const targetPath = '/' + req.params[0] + (req._parsedUrl.search || '');
  const fwdHeaders = Object.assign({}, req.headers);
  delete fwdHeaders['host'];
  delete fwdHeaders['connection'];
  delete fwdHeaders['content-length'];
  fwdHeaders['host'] = targetHost;

  const bodyChunks = [];
  req.on('data', c => bodyChunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(bodyChunks);
    const reqOpts = {
      hostname: targetHost, port: 443,
      path: targetPath, method: req.method,
      headers: Object.assign({}, fwdHeaders, body.length ? { 'content-length': body.length } : {}),
      timeout: 30000
    };
    const upstream = https.request(reqOpts, (upRes) => {
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.pipe(res);
    });
    upstream.on('error', (e) => {
      console.error(`[Relay] ${targetHost}${targetPath} error: ${e.message}`);
      if (!res.headersSent) res.status(502).json({ ok: false, error: 'upstream_error' });
    });
    upstream.on('timeout', () => {
      upstream.destroy();
      if (!res.headersSent) res.status(504).json({ ok: false, error: 'upstream_timeout' });
    });
    if (body.length) upstream.write(body);
    upstream.end();
  });
});

/* Legacy CONNECT tunnel (kept for direct-IP connections bypassing Cloudflare) */
const PROXY_ALLOWED_HOSTS = new Set([
  'api2.cursor.sh', 'api.cursor.com', 'cursor.sh',
  'api.cursor.sh', 'repo42.cursor.sh', 'marketplace.cursorapi.com',
  'api2.cursor.sh:443', 'api.cursor.com:443', 'cursor.sh:443',
  'api.cursor.sh:443', 'repo42.cursor.sh:443', 'marketplace.cursorapi.com:443'
]);

function setupConnectProxy(server) {
  server.on('connect', (req, clientSocket, head) => {
    const target = req.url;
    const [hostname, port] = target.split(':');
    const destPort = parseInt(port) || 443;

    if (!PROXY_ALLOWED_HOSTS.has(target) && !PROXY_ALLOWED_HOSTS.has(hostname)) {
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    const serverSocket = net.connect(destPort, hostname, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      serverSocket.write(head);
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on('error', (err) => {
      console.error(`[Proxy] ${target} error: ${err.message}`);
      try { clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch(e) {}
      clientSocket.destroy();
    });

    clientSocket.on('error', () => { try { serverSocket.destroy(); } catch(e) {} });
    serverSocket.setTimeout(30000, () => { serverSocket.destroy(); clientSocket.destroy(); });
  });
}

setupConnectProxy(httpServer);

httpServer.listen(PORT, () => {
  console.log(`[Michael VIP License Server] HTTP 运行在 http://localhost:${PORT}`);
  console.log(`  CONNECT 代理已启用 (Cursor API 白名单)`);
});

// Ensure shared content tables exist at boot (versions + announcements).
ensureContentTables().then(() => console.log('[Michael VIP] content tables ready')).catch(e => console.error('[Michael VIP] ensureContentTables:', e.message));

if (SSL_CERT && SSL_KEY) {
  try {
    const sslOpts = {
      cert: fs.readFileSync(SSL_CERT),
      key: fs.readFileSync(SSL_KEY),
    };
    if (SSL_CA) sslOpts.ca = fs.readFileSync(SSL_CA);
    const httpsServer = https.createServer(sslOpts, app);
    setupWss(httpsServer);
    setupConnectProxy(httpsServer);
    httpsServer.listen(SSL_PORT, () => {
      console.log(`[Michael VIP License Server] HTTPS 运行在 https://localhost:${SSL_PORT}`);
      console.log(`  WSS 联机: wss://localhost:${SSL_PORT}/ws/relay`);
      console.log(`  CONNECT 代理已启用 (Cursor API 白名单)`);
    });
  } catch (e) {
    console.error('[SSL] HTTPS 启动失败:', e.message);
    console.error('[SSL] 请检查 SSL_CERT / SSL_KEY 路径是否正确');
  }
} else {
  console.log('[SSL] 未配置 SSL_CERT / SSL_KEY，仅 HTTP 模式');
  console.log('[SSL] 启用 HTTPS: SSL_CERT=/path/to/cert.pem SSL_KEY=/path/to/key.pem node server.js');
}

console.log(`  激活: POST /api/license/activate`);
console.log(`  验证: POST /api/license/validate`);
console.log(`  解绑: POST /api/license/deactivate`);
console.log(`  联机: WS(S) /ws/relay`);
console.log(`  生成卡密: POST /api/admin/generate (需要 x-admin-key)`);
