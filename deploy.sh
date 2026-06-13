#!/usr/bin/env bash
#
# Michael Cursor 全套迁移部署脚本
# 在目标服务器(103.39.67.137)以 root 运行:
#   git clone https://github.com/fendoushaonian/Michael_Cursor_Relay.git
#   cd Michael_Cursor_Relay && bash deploy.sh <解密口令>
#
set -euo pipefail

PASS="${1:-}"
if [ -z "$PASS" ]; then
  echo "用法: bash deploy.sh <解密口令>"
  echo "  解密口令由 Devin 在聊天中提供"
  exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date +%s)

echo "========================================"
echo " Michael Cursor 迁移部署"
echo " 时间: $(date)"
echo "========================================"

# ---------- 1. 检查依赖 ----------
echo "[1/9] 检查依赖..."
for cmd in node npm openssl; do
  if ! command -v $cmd &>/dev/null; then
    echo "!! 缺少 $cmd，正在安装..."
    if command -v apt-get &>/dev/null; then
      apt-get update -qq && apt-get install -y -qq nodejs npm openssl 2>/dev/null || true
    fi
  fi
done
command -v node &>/dev/null || { echo "ERROR: node 未安装，请先安装 Node.js 18+"; exit 1; }
echo "  node $(node -v), npm $(npm -v 2>/dev/null || echo N/A)"

# 检查 MySQL
MYSQL_CMD=""
if command -v mysql &>/dev/null; then
  MYSQL_CMD="mysql"
elif [ -x /usr/bin/mysql ]; then
  MYSQL_CMD="/usr/bin/mysql"
fi
# Try connect
mysql_exec() {
  if $MYSQL_CMD -u root -e "SELECT 1" &>/dev/null 2>&1; then
    $MYSQL_CMD -u root "$@"
  elif $MYSQL_CMD -u root -p'Michael@2026' -e "SELECT 1" &>/dev/null 2>&1; then
    $MYSQL_CMD -u root -p'Michael@2026' "$@"
  else
    echo "!! 无法连接 MySQL (尝试了 auth_socket 和密码 Michael@2026)"
    echo "   请手动确认 MySQL root 登录方式后重跑"
    return 1
  fi
}

# ---------- 2. 解密敏感文件 ----------
echo "[2/9] 解密敏感文件..."
SECRETS_DIR="/tmp/michael-mig-secrets-${TIMESTAMP}"
mkdir -p "$SECRETS_DIR"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -in "${REPO_DIR}/secret-bundle.tar.gz.enc" \
  -pass pass:"${PASS}" | tar xzf - -C "$SECRETS_DIR"
echo "  解密成功: $(ls "$SECRETS_DIR")"

# ---------- 3. 停止现有服务 ----------
echo "[3/9] 停止现有服务(如果在运行)..."
for svc in michael-vip kc-server mcursor-proxy; do
  systemctl stop "$svc" 2>/dev/null && echo "  已停止 $svc" || true
done

# ---------- 4. 备份现有数据 ----------
echo "[4/9] 备份现有数据..."
BACKUP_DIR="/root/michael-backup-${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"
[ -d /opt/michael-vip ] && cp -a /opt/michael-vip "$BACKUP_DIR/" && echo "  备份 /opt/michael-vip -> $BACKUP_DIR"
[ -d /opt/kc-server ] && cp -a /opt/kc-server "$BACKUP_DIR/" && echo "  备份 /opt/kc-server -> $BACKUP_DIR"
if [ -n "$MYSQL_CMD" ]; then
  if command -v mysqldump &>/dev/null; then
    mysqldump -u root michael_vip > "$BACKUP_DIR/michael_vip_old.sql" 2>/dev/null \
      && echo "  备份旧数据库 -> $BACKUP_DIR/michael_vip_old.sql" || true
  fi
fi
echo "  备份目录: $BACKUP_DIR"

# ---------- 5. 部署代码 ----------
echo "[5/9] 部署代码..."
# michael-vip
mkdir -p /opt/michael-vip/public/dl
cp -f "${REPO_DIR}/michael-vip/server.js" /opt/michael-vip/
cp -f "${REPO_DIR}/michael-vip/package.json" /opt/michael-vip/
cp -f "${REPO_DIR}/michael-vip/package-lock.json" /opt/michael-vip/
cp -f "${REPO_DIR}/michael-vip/public/admin.html" /opt/michael-vip/public/ 2>/dev/null || true
cp -f "${REPO_DIR}"/michael-vip/public/dl/*.vsix /opt/michael-vip/public/dl/ 2>/dev/null || true
echo "  michael-vip 代码已部署"

# kc-server
mkdir -p /opt/kc-server/public/vendor /opt/kc-server/data
cp -f "${REPO_DIR}/kc-server/server.js" /opt/kc-server/
cp -f "${REPO_DIR}/kc-server/cursor-proxy.js" /opt/kc-server/
cp -f "${REPO_DIR}/kc-server/init-db.js" /opt/kc-server/
cp -f "${REPO_DIR}/kc-server/package.json" /opt/kc-server/
cp -f "${REPO_DIR}/kc-server/package-lock.json" /opt/kc-server/
cp -rf "${REPO_DIR}/kc-server/public/"* /opt/kc-server/public/ 2>/dev/null || true
echo "  kc-server 代码已部署"

# ---------- 6. 放置敏感文件 ----------
echo "[6/9] 放置环境变量和证书..."
cp -f "$SECRETS_DIR/michael-vip.env" /opt/michael-vip/.env
cp -f "$SECRETS_DIR/server.cert" /opt/michael-vip/
cp -f "$SECRETS_DIR/server.key" /opt/michael-vip/
cp -f "$SECRETS_DIR"/kc-data/kc.db* /opt/kc-server/data/ 2>/dev/null || true
echo "  .env / cert / key / kc.db 已就位"

# ---------- 7. npm install ----------
echo "[7/9] 安装 npm 依赖..."
cd /opt/michael-vip && npm install --production --no-audit --no-fund 2>&1 | tail -3
cd /opt/kc-server && npm install --production --no-audit --no-fund 2>&1 | tail -3
echo "  依赖安装完成"

# ---------- 8. 导入数据库 ----------
echo "[8/9] 导入 michael_vip 数据库..."
if [ -n "$MYSQL_CMD" ]; then
  # 确保数据库存在
  mysql_exec -e "CREATE DATABASE IF NOT EXISTS michael_vip CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null
  # 导入(DROP + CREATE + INSERT，会替换现有数据)
  mysql_exec michael_vip < "$SECRETS_DIR/michael_vip.sql"
  ROW_COUNT=$(mysql_exec -N -e "SELECT COUNT(*) FROM michael_vip.license_keys" 2>/dev/null || echo "?")
  echo "  数据库导入完成, license_keys 行数: $ROW_COUNT"
else
  echo "!! MySQL 客户端未找到。请手动安装 mysql-client 后重跑，或手动导入:"
  echo "   mysql -u root michael_vip < $SECRETS_DIR/michael_vip.sql"
fi

# ---------- 9. 写入 systemd + 启动服务 ----------
echo "[9/9] 配置 systemd 并启动服务..."

cat > /etc/systemd/system/michael-vip.service <<'UNIT'
[Unit]
Description=Michael VIP License Server
After=network.target mysql.service

[Service]
Type=simple
WorkingDirectory=/opt/michael-vip
EnvironmentFile=/opt/michael-vip/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# kc-server env file
cp -f "$SECRETS_DIR/kc-server.env" /opt/kc-server/.env

cat > /etc/systemd/system/kc-server.service <<'UNIT'
[Unit]
Description=KC-MCP Admin Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/kc-server
EnvironmentFile=/opt/kc-server/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# mcursor-proxy env file
cp -f "$SECRETS_DIR/mcursor-proxy.env" /opt/kc-server/.proxy.env

cat > /etc/systemd/system/mcursor-proxy.service <<'UNIT'
[Unit]
Description=Michael Cursor VIP - Cursor API Proxy
After=network.target kc-server.service

[Service]
Type=simple
WorkingDirectory=/opt/kc-server
EnvironmentFile=/opt/kc-server/.proxy.env
ExecStart=/usr/bin/node cursor-proxy.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
for svc in michael-vip kc-server mcursor-proxy; do
  systemctl enable "$svc" 2>/dev/null
  systemctl start "$svc"
  sleep 2
  if systemctl is-active --quiet "$svc"; then
    echo "  $svc -> 运行中"
  else
    echo "  !! $svc 启动失败，查看日志: journalctl -u $svc -n 30"
  fi
done

# 清理解密的临时文件
rm -rf "$SECRETS_DIR"

echo ""
echo "========================================"
echo " 部署完成！"
echo "========================================"
echo " 备份位置: $BACKUP_DIR"
echo ""
echo " 健康检查:"
sleep 3
curl -s --max-time 5 http://127.0.0.1:3900/api/status 2>/dev/null && echo "" || echo " michael-vip: 未响应(等几秒再试)"
curl -s --max-time 5 http://127.0.0.1:8900/api/health 2>/dev/null && echo "" || echo " kc-server: 未响应"
echo ""
echo " 如需回滚: cp -a $BACKUP_DIR/* /opt/ && systemctl restart michael-vip kc-server mcursor-proxy"
echo "========================================"
