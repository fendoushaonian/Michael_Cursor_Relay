# Michael Cursor Relay - Migration Transfer

Migration bundle for deploying Michael Cursor services to a new server.

## Contents

- `michael-vip/` - License validation server (port 3900 HTTP / 443 HTTPS+WSS)
- `kc-server/` - KC-MCP Admin backend (port 8900) + Cursor API proxy (port 8901)
- `secret-bundle.tar.gz.enc` - Encrypted database dump + env secrets + certs
- `deploy.sh` - One-command deployment script

## Deploy

```bash
ssh -p 19537 root@103.39.67.137
git clone https://github.com/fendoushaonian/Michael_Cursor_Relay.git
cd Michael_Cursor_Relay
bash deploy.sh <PASSPHRASE>
```

The passphrase is provided separately (not in this repo).

## What deploy.sh does

1. Decrypts the secret bundle (DB dump, .env, SSL certs, kc.db)
2. Backs up existing /opt/michael-vip, /opt/kc-server, and database
3. Deploys code + npm install
4. Imports michael_vip database (205 license keys, 212 device bindings, etc.)
5. Writes systemd units and starts all 3 services
6. Runs health checks

## Rollback

Backup is saved to `/root/michael-backup-<timestamp>/`. To rollback:
```bash
cp -a /root/michael-backup-<timestamp>/* /opt/
systemctl restart michael-vip kc-server mcursor-proxy
```
