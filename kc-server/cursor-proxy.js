/**
 * Michael Cursor VIP — Cursor API Proxy Server
 * 代理 Cursor 的 AI 聊天请求，验证卡密后转发给上游 API
 * 支持 HTTP 和 WebSocket 连接
 */
const http = require('http');
const https = require('https');
const { URL } = require('url');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const PROXY_PORT = parseInt(process.env.PROXY_PORT || '8901');
const SIGN_SECRET = process.env.SIGN_SECRET;
const CURSOR_API_URL = process.env.CURSOR_API_URL || 'https://api2.cursor.sh';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

if (!SIGN_SECRET) {
  console.error('❌ [FATAL] 必须设置环境变量: SIGN_SECRET');
  process.exit(1);
}

// ═══ Database ═══
const DB_PATH = path.join(__dirname, 'data', 'kc.db');
if (!fs.existsSync(DB_PATH)) {
  console.error('❌ Database not found at', DB_PATH);
  process.exit(1);
}
const db = new Database(DB_PATH, { readonly: false });
db.pragma('journal_mode = WAL');

// ═══ License validation ═══
function validateLicense(licenseKey, deviceHash) {
  if (!licenseKey || !deviceHash) return { valid: false, reason: '缺少卡密或设备信息' };

  const banned = db.prepare("SELECT id FROM device_blacklist WHERE device_hash=? AND status='active'").get(deviceHash);
  if (banned) return { valid: false, reason: '设备已被封禁', action: 'kill' };

  const key = db.prepare('SELECT * FROM license_key WHERE license_key=?').get(licenseKey);
  if (!key) return { valid: false, reason: '无效的卡密' };
  if (key.status === 'disabled') return { valid: false, reason: '卡密已被禁用' };
  if (key.status === 'expired') return { valid: false, reason: '卡密已过期' };
  if (key.expires_at && new Date(key.expires_at) < new Date()) {
    db.prepare("UPDATE license_key SET status='expired' WHERE id=?").run(key.id);
    return { valid: false, reason: '卡密已过期' };
  }

  if (key.device_hash && key.device_hash !== deviceHash) {
    return { valid: false, reason: '设备不匹配，请先解绑' };
  }
  if (!key.device_hash) {
    db.prepare('UPDATE license_key SET device_hash=?, device_id=?, activated_at=CURRENT_TIMESTAMP WHERE id=?')
      .run(deviceHash, deviceHash.slice(0, 16), key.id);
  }

  const account = pickAccount(key);
  if (!account) return { valid: false, reason: '暂无可用账号，请稍后重试' };

  return { valid: true, license: key, account };
}

// ═══ Account pool: pick a usable account ═══
function pickAccount(license) {
  if (license.assigned_license_id) {
    const assigned = db.prepare("SELECT * FROM cursor_account WHERE id=? AND status='active'").get(license.assigned_license_id);
    if (assigned) return assigned;
  }

  const accounts = db.prepare("SELECT * FROM cursor_account WHERE status='active' ORDER BY RANDOM()").all();
  if (accounts.length === 0) return null;

  for (const acct of accounts) {
    if (acct.usage_quota > 0 && acct.usage_used >= acct.usage_quota) continue;
    db.prepare('UPDATE license_key SET assigned_license_id=? WHERE id=?').run(acct.id, license.id);
    return acct;
  }

  return accounts[0];
}

// ═══ HMAC signature verification ═══
function verifySign(headers, body) {
  const ts = headers['x-kc-ts'];
  const nonce = headers['x-kc-nonce'];
  const sign = headers['x-kc-sign'];
  const device = headers['x-kc-device'];
  if (!ts || !nonce || !sign || !device) return { valid: false, reason: '缺少签名参数' };

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(ts)) > 300) return { valid: false, reason: '请求已过期' };

  const used = db.prepare('SELECT nonce FROM used_nonce WHERE nonce=?').get(nonce);
  if (used) return { valid: false, reason: '重复请求' };
  db.prepare('INSERT OR IGNORE INTO used_nonce (nonce, ts) VALUES (?,?)').run(nonce, parseInt(ts));

  const expected = crypto.createHmac('sha256', SIGN_SECRET)
    .update(`${ts}:${nonce}:${device}:${body}`)
    .digest('hex');
  if (sign !== expected) return { valid: false, reason: '签名验证失败' };

  return { valid: true, device };
}

// ═══ Logging ═══
function log(level, ...args) {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  if (levels[level] >= levels[LOG_LEVEL]) {
    const ts = new Date().toISOString();
    console.log(`[${ts}] [${level.toUpperCase()}]`, ...args);
  }
}

function logVerify(licenseKey, device, action, ip, success, message) {
  try {
    db.prepare('INSERT INTO license_verify_log (license_key, device_hash, action, ip, success, message) VALUES (?,?,?,?,?,?)')
      .run(licenseKey || '', device || '', action, ip || '', success ? 1 : 0, message || '');
  } catch {}
}

// ═══ Proxy request to upstream Cursor API ═══
function proxyToUpstream(req, res, account, targetPath) {
  const upstream = new URL(targetPath, CURSOR_API_URL);

  const proxyHeaders = { ...req.headers };
  delete proxyHeaders['x-kc-ts'];
  delete proxyHeaders['x-kc-nonce'];
  delete proxyHeaders['x-kc-sign'];
  delete proxyHeaders['x-kc-device'];
  delete proxyHeaders['x-kc-license'];
  delete proxyHeaders['host'];

  if (account.token) {
    proxyHeaders['authorization'] = `Bearer ${account.token}`;
  }
  if (account.workos_token) {
    proxyHeaders['x-workos-token'] = account.workos_token;
  }
  proxyHeaders['host'] = upstream.hostname;

  const options = {
    hostname: upstream.hostname,
    port: upstream.port || 443,
    path: upstream.pathname + upstream.search,
    method: req.method,
    headers: proxyHeaders,
    timeout: 120000,
  };

  const protocol = upstream.protocol === 'https:' ? https : http;
  const proxyReq = protocol.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    log('error', 'Proxy error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'upstream_error', message: err.message }));
    }
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    if (!res.headersSent) {
      res.writeHead(504, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'upstream_timeout' }));
    }
  });

  req.pipe(proxyReq);
}

// ═══ Rate limiter (in-memory) ═══
const rateLimits = new Map();
function checkRateLimit(key, maxReqs, windowMs) {
  const now = Date.now();
  let bucket = rateLimits.get(key);
  if (!bucket || now - bucket.start > windowMs) {
    bucket = { count: 0, start: now };
    rateLimits.set(key, bucket);
  }
  bucket.count++;
  return bucket.count <= maxReqs;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateLimits) {
    if (now - bucket.start > 900000) rateLimits.delete(key);
  }
}, 60000);

// ═══ HTTP Server ═══
const server = http.createServer((req, res) => {
  const clientIp = req.headers['x-real-ip'] || req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

  if (req.url === '/health' || req.url === '/v1/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'cursor-proxy', timestamp: new Date().toISOString() }));
    return;
  }

  if (!req.url.startsWith('/v1/')) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
    return;
  }

  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    const licenseKey = req.headers['x-kc-license'];
    const device = req.headers['x-kc-device'];

    if (!checkRateLimit(clientIp, 60, 60000)) {
      log('warn', 'Rate limited:', clientIp);
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'rate_limited', message: '请求过于频繁' }));
      return;
    }

    const sigResult = verifySign(req.headers, body);
    if (!sigResult.valid) {
      log('warn', 'Sign verify failed:', sigResult.reason, clientIp);
      logVerify(licenseKey, device, 'proxy', clientIp, false, sigResult.reason);
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'auth_failed', message: sigResult.reason }));
      return;
    }

    const licenseResult = validateLicense(licenseKey, sigResult.device);
    if (!licenseResult.valid) {
      log('warn', 'License invalid:', licenseResult.reason, licenseKey?.slice(0, 8));
      logVerify(licenseKey, device, 'proxy', clientIp, false, licenseResult.reason);
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'license_invalid',
        message: licenseResult.reason,
        action: licenseResult.action
      }));
      return;
    }

    logVerify(licenseKey, device, 'proxy', clientIp, true, 'ok');
    log('info', `Proxy: ${req.method} ${req.url} → ${licenseResult.account.email} [${clientIp}]`);
    trackSession(licenseKey, device, clientIp, licenseResult.account.email);

    const _proxyStart = Date.now();
    const _origEnd = res.end.bind(res);
    res.end = function() {
      const elapsed = Date.now() - _proxyStart;
      logProxyRequest(licenseKey, clientIp, licenseResult.account.email, req.url, res.statusCode, elapsed, res.statusCode < 500, '');
      return _origEnd.apply(this, arguments);
    };

    proxyToUpstream(req, res, licenseResult.account, req.url);
  });
});

// ═══ WebSocket upgrade (for streaming chat) ═══
server.on('upgrade', (req, socket, head) => {
  const clientIp = req.headers['x-real-ip'] || req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  const licenseKey = req.headers['x-kc-license'];
  const device = req.headers['x-kc-device'];

  const licenseResult = validateLicense(licenseKey, device);
  if (!licenseResult.valid) {
    log('warn', 'WS upgrade denied:', licenseResult.reason);
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }

  log('info', `WS Upgrade: ${req.url} → ${licenseResult.account.email} [${clientIp}]`);

  const upstream = new URL(req.url, CURSOR_API_URL.replace('https://', 'wss://').replace('http://', 'ws://'));
  const wsOptions = {
    hostname: upstream.hostname,
    port: upstream.port || 443,
    path: upstream.pathname + upstream.search,
    method: 'GET',
    headers: {
      ...req.headers,
      host: upstream.hostname,
      authorization: `Bearer ${licenseResult.account.token}`,
    },
  };

  delete wsOptions.headers['x-kc-ts'];
  delete wsOptions.headers['x-kc-nonce'];
  delete wsOptions.headers['x-kc-sign'];
  delete wsOptions.headers['x-kc-device'];
  delete wsOptions.headers['x-kc-license'];

  const proxyReq = https.request(wsOptions);
  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
      Object.entries(proxyRes.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') +
      '\r\n\r\n');
    if (proxyHead.length > 0) socket.write(proxyHead);
    proxySocket.pipe(socket);
    socket.pipe(proxySocket);
    proxySocket.on('error', () => socket.destroy());
    socket.on('error', () => proxySocket.destroy());
  });
  proxyReq.on('error', (err) => {
    log('error', 'WS proxy error:', err.message);
    socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    socket.destroy();
  });
  proxyReq.end();
});

// ═══ Session tracking ═══
const activeSessions = new Map();

function trackSession(licenseKey, device, clientIp, accountEmail) {
  const key = device || clientIp;
  let session = activeSessions.get(key);
  if (!session) {
    session = { license_key: licenseKey, device_hash: device, client_ip: clientIp, account_email: accountEmail, requests_count: 0, connected_at: Date.now() };
    activeSessions.set(key, session);
  }
  session.requests_count++;
  session.last_request_at = Date.now();
  session.client_ip = clientIp;
  session.account_email = accountEmail;
}

function logProxyRequest(licenseKey, clientIp, accountEmail, path, statusCode, responseTimeMs, success, errorMsg) {
  try {
    db.prepare('INSERT INTO cloud_proxy_log (license_key, client_ip, account_email, request_path, status_code, response_time_ms, success, error_message) VALUES (?,?,?,?,?,?,?,?)')
      .run(licenseKey || '', clientIp || '', accountEmail || '', path || '', statusCode || 0, responseTimeMs || 0, success ? 1 : 0, errorMsg || '');
  } catch {}
}

setInterval(() => {
  const now = Date.now();
  for (const [key, session] of activeSessions) {
    if (now - session.last_request_at > 600000) {
      activeSessions.delete(key);
    }
  }
}, 60000);

// ═══ Heartbeat to admin server ═══
const ADMIN_PORT = parseInt(process.env.PORT || '8900');
function sendHeartbeat() {
  try {
    const os = require('os');
    const sessions = Array.from(activeSessions.values());
    const payload = JSON.stringify({
      server_ip: getLocalIP(),
      proxy_port: PROXY_PORT,
      active_sessions: sessions.length,
      cpu_usage: os.loadavg()[0],
      memory_usage: Math.round((1 - os.freemem() / os.totalmem()) * 100),
      sessions: sessions.map(s => ({
        license_key: s.license_key, device_hash: s.device_hash,
        client_ip: s.client_ip, account_email: s.account_email,
        requests_count: s.requests_count
      }))
    });
    const req = http.request({
      hostname: '127.0.0.1', port: ADMIN_PORT,
      path: '/internal/cloud/heartbeat', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      timeout: 5000
    });
    req.on('error', () => {});
    req.write(payload);
    req.end();
  } catch {}
}

function getLocalIP() {
  try {
    const nets = require('os').networkInterfaces();
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) return net.address;
      }
    }
  } catch {}
  return '127.0.0.1';
}

setInterval(sendHeartbeat, 30000);

server.listen(PROXY_PORT, '0.0.0.0', () => {
  console.log(`✅ Cursor API Proxy running on port ${PROXY_PORT}`);
  console.log(`   Upstream: ${CURSOR_API_URL}`);
  console.log(`   Proxy:    http://0.0.0.0:${PROXY_PORT}/v1/`);
  setTimeout(sendHeartbeat, 3000);
});
