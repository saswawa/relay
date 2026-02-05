#!/bin/bash
set -e

# ==========================================
# Socks5 转 VLESS 极简中转面板 (1.1 一键兼容版)
# 基于你提供的 1.0 版本修改：修复 CRLF/PEP668/服务覆盖/防火墙
# 适用系统: Debian 10/11/12/13, Ubuntu 20/22/24
# ==========================================

# 0. 自愈：如果脚本被 Windows 换行污染（CRLF），自动清理当前脚本的 \r
# （这句不会影响正常 LF 文件）
sed -i 's/\r$//' "$0" 2>/dev/null || true

# 1. 强制检查 Root 权限
if [ "$EUID" -ne 0 ]; then
  echo "❌ 错误: 请使用 'sudo -i' 切换到 root 用户后再运行此脚本！"
  exit 1
fi

echo ">>> [1/8] 正在更新系统并安装环境..."
apt-get update -q

# 基础依赖
apt-get install -y curl socat openssl ca-certificates

# Python：优先用系统包（不触发 PEP668）
# 有的系统没有 python3-flask，我们做兜底 venv
apt-get install -y python3 python3-venv >/dev/null 2>&1 || true
apt-get install -y python3-flask >/dev/null 2>&1 || true

echo ">>> [2/8] 正在安装 Sing-box..."
bash <(curl -fsSL https://sing-box.app/deb-install.sh)

echo ">>> [3/8] 创建项目目录..."
WORK_DIR="/root/sbox-relay"
mkdir -p "$WORK_DIR/templates"
cd "$WORK_DIR"

echo ">>> [4/8] 生成 Reality 加密密钥..."
KEYS=$(sing-box generate reality-keypair)
PRIVATE_KEY=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
PUBLIC_KEY=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 4)
HOST_IP=$(curl -s ifconfig.me || echo "127.0.0.1")

echo "   - 公钥: $PUBLIC_KEY"
echo "   - 本机IP: $HOST_IP"

echo ">>> [5/8] 写入 Python 后端程序..."
cat > "$WORK_DIR/app.py" <<EOF
import json
import os
import subprocess
import uuid
from flask import Flask, render_template, request, redirect

app = Flask(__name__)
WORK_DIR = "/root/sbox-relay"
DATA_FILE = f"{WORK_DIR}/data.json"
SBOX_CONFIG = "/etc/sing-box/config.json"

PRIVATE_KEY = "${PRIVATE_KEY}"
PUBLIC_KEY = "${PUBLIC_KEY}"
SHORT_ID = "${SHORT_ID}"
HOST_IP = "${HOST_IP}"

def load_data():
    if not os.path.exists(DATA_FILE): return []
    try:
        with open(DATA_FILE, 'r') as f: return json.load(f)
    except: return []

def save_data(data):
    with open(DATA_FILE, 'w') as f: json.dump(data, f, indent=2)

def generate_sbox_config(rules):
    config = {
        "log": {"level": "info", "output": "/var/log/sing-box.log"},
        "inbounds": [],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {"rules": [], "final": "direct"}
    }

    for rule in rules:
        in_tag = f"in_{rule['port']}"
        out_tag = f"out_{rule['port']}"

        config['inbounds'].append({
            "type": "vless",
            "tag": in_tag,
            "listen": "::",
            "listen_port": int(rule['port']),
            "users": [{"uuid": rule['uuid'], "flow": "xtls-rprx-vision"}],
            "tls": {
                "enabled": True,
                "server_name": "www.microsoft.com",
                "reality": {
                    "enabled": True,
                    "handshake": {"server": "www.microsoft.com", "server_port": 443},
                    "private_key": PRIVATE_KEY,
                    "short_id": [SHORT_ID]
                }
            }
        })

        config['outbounds'].insert(0, {
            "type": "socks",
            "tag": out_tag,
            "server": rule['s_ip'],
            "server_port": int(rule['s_port']),
            "username": rule.get('s_user',''),
            "password": rule.get('s_pass','')
        })

        config['route']['rules'].insert(0, {
            "inbound": [in_tag],
            "outbound": out_tag
        })

    with open(SBOX_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)

    os.system("systemctl reload sing-box || systemctl restart sing-box")

@app.route('/')
def index():
    rules = load_data()
    try:
        current_ip = subprocess.check_output("curl -s ifconfig.me", shell=True).decode().strip()
    except:
        current_ip = HOST_IP

    for r in rules:
        r['link'] = f"vless://{r['uuid']}@{current_ip}:{r['port']}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={PUBLIC_KEY}&sid={SHORT_ID}#{r['remark']}"
    return render_template('index.html', rules=rules)

@app.route('/add', methods=['POST'])
def add():
    rules = load_data()
    try:
        new_rule = {
            "id": str(uuid.uuid4())[:8],
            "remark": request.form.get('remark'),
            "port": int(request.form.get('port')),
            "uuid": str(uuid.uuid4()),
            "s_ip": request.form.get('s_ip'),
            "s_port": int(request.form.get('s_port')),
            "s_user": request.form.get('s_user', ''),
            "s_pass": request.form.get('s_pass', '')
        }
        rules.append(new_rule)
        save_data(rules)
        generate_sbox_config(rules)
    except Exception as e:
        return f"Error: {str(e)}", 400
    return redirect('/')

@app.route('/del/<id>')
def delete(id):
    rules = load_data()
    rules = [r for r in rules if r['id'] != id]
    save_data(rules)
    generate_sbox_config(rules)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

echo ">>> [5.5/8] 确保 Flask 可用（PEP668 兜底）..."
# 如果系统没有 flask 模块，则创建 venv 安装 flask（不污染系统环境）
python3 -c "import flask" >/dev/null 2>&1 || {
  echo "   - 系统未提供 python3-flask，启用 venv 安装 flask..."
  python3 -m venv "$WORK_DIR/venv"
  "$WORK_DIR/venv/bin/pip" -q install -U pip
  "$WORK_DIR/venv/bin/pip" -q install flask
}

echo ">>> [6/8] 写入前端页面..."
cat > "$WORK_DIR/templates/index.html" <<'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Socks5 Relay Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body{background:#f4f6f9;font-family:sans-serif;}.card{border:none;border-radius:10px;box-shadow:0 0 15px rgba(0,0,0,0.05);}</style>
</head>
<body>
<div class="container py-5">
    <div class="card">
        <div class="card-header bg-primary text-white text-center py-3">
            <h4 class="mb-0">🚀 Socks5 加速中转面板</h4>
        </div>
        <div class="card-body p-4">
            <form action="/add" method="POST" class="row g-3 mb-4 pb-4 border-bottom">
                <div class="col-md-3">
                    <label class="form-label text-muted small">备注名</label>
                    <input type="text" name="remark" class="form-control" placeholder="例如: 店铺A" required>
                </div>
                <div class="col-md-2">
                    <label class="form-label text-muted small">中转端口 (入口)</label>
                    <input type="number" name="port" class="form-control" placeholder="20001" required>
                </div>
                <div class="col-md-3">
                    <label class="form-label text-muted small">Socks5 IP (目标)</label>
                    <input type="text" name="s_ip" class="form-control" placeholder="1.2.3.4" required>
                </div>
                <div class="col-md-2">
                    <label class="form-label text-muted small">Socks5 端口</label>
                    <input type="number" name="s_port" class="form-control" placeholder="1080" required>
                </div>
                <div class="col-md-2">
                    <label class="form-label text-muted small">Socks5 账号/密码</label>
                    <div class="input-group">
                        <input type="text" name="s_user" class="form-control" placeholder="User">
                        <input type="text" name="s_pass" class="form-control" placeholder="Pass">
                    </div>
                </div>
                <div class="col-12 mt-4">
                    <button type="submit" class="btn btn-primary w-100 fw-bold shadow-sm">➕ 添加并生成加速链接</button>
                </div>
            </form>

            <div class="table-responsive">
                <table class="table table-hover align-middle">
                    <thead class="table-light">
                        <tr>
                            <th>备注</th>
                            <th>中转端口</th>
                            <th>目标 IP</th>
                            <th style="width: 40%;">VLESS 链接 (点击复制)</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for r in rules %}
                        <tr>
                            <td><span class="badge bg-secondary">{{ r.remark }}</span></td>
                            <td class="fw-bold text-success">:{{ r.port }}</td>
                            <td class="text-muted small">{{ r.s_ip }}:{{ r.s_port }}</td>
                            <td>
                                <input type="text" class="form-control form-control-sm bg-white" value="{{ r.link }}"
                                       onclick="this.select();document.execCommand('copy');this.classList.add('is-valid');" readonly>
                            </td>
                            <td><a href="/del/{{ r.id }}" class="btn btn-outline-danger btn-sm">删除</a></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        <div class="card-footer text-center text-muted small bg-white py-3">
            已自动生成 Reality 密钥 | 面板端口: 5000
        </div>
    </div>
</div>
</body>
</html>
HTML_EOF

echo ">>> [7/8] 配置系统服务 (使用 Root 运行)..."
# 面板服务：如果有 venv，就用 venv 的 python；否则用系统 python
PYBIN="/usr/bin/python3"
[ -x "$WORK_DIR/venv/bin/python" ] && PYBIN="$WORK_DIR/venv/bin/python"

cat > /etc/systemd/system/sbox-web.service <<EOF
[Unit]
Description=Singbox Web Panel
After=network.target

[Service]
User=root
WorkingDirectory=$WORK_DIR
ExecStart=$PYBIN app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 用 systemd override 替代直接改 /lib/systemd/system（更稳）
mkdir -p /etc/systemd/system/sing-box.service.d
cat > /etc/systemd/system/sing-box.service.d/override.conf <<EOF
[Service]
User=root
Group=root
EOF

# 创建日志文件并给权限（不再 777，给可写即可）
touch /var/log/sing-box.log
chmod 666 /var/log/sing-box.log || true

echo ">>> [8/8] 放行端口并启动..."
# 优先 ufw，没有就尽量用 iptables 放行 5000
if command -v ufw >/dev/null 2>&1; then
  ufw allow 5000/tcp >/dev/null 2>&1 || true
else
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport 5000 -j ACCEPT >/dev/null 2>&1 || \
      iptables -I INPUT -p tcp --dport 5000 -j ACCEPT
  fi
fi

systemctl daemon-reload
systemctl enable sbox-web sing-box >/dev/null 2>&1
systemctl restart sbox-web sing-box

IP=$(curl -s ifconfig.me || echo "$HOST_IP")
echo ""
echo "=========================================================="
echo "✅ 安装成功！(基于 1.0 改进版)"
echo "📂 后台地址: http://${IP}:5000"
echo "=========================================================="
