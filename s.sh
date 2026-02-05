#!/bin/bash
set -e

# ==========================================
# Socks5 转 VLESS 极简中转面板 (2.5 不死安装版)
# 变更日志:
# 2.5: 增加 Sing-box 安装备选源 (解决 curl TLS 错误)
# 2.4: 强制 IPv4 + Google DNS
# 2.3: 端口迁移 30000+
# 适用系统: Debian 10/11/12/13, Ubuntu 20/22/24
# ==========================================

sed -i 's/\r$//' "$0" 2>/dev/null || true

if [ "$EUID" -ne 0 ]; then
  echo "❌ 错误: 请使用 'sudo -i' 切换到 root 用户后再运行此脚本！"
  exit 1
fi

LOG_FILE="/var/log/sing-box-install.log"

install_singbox() {
    echo ">>> [2/8] 正在安装 Sing-box..."
    
    # 尝试1: 官方脚本
    echo "   - 尝试方式 1: 官方脚本安装..."
    if bash <(curl -fsSL https://sing-box.app/deb-install.sh) >/dev/null 2>&1; then
        echo "   ✅ 官方脚本安装成功!"
        return 0
    fi
    echo "   ⚠️ 方式 1 失败，尝试方式 2..."
    
    # 尝试2: GitHub Release 直接下载 (amd64, v1.10.7 稳定版)
    SBOX_VER="v1.10.7"
    if [ "$(uname -m)" = "x86_64" ]; then
        ARCH="amd64"
    elif [ "$(uname -m)" = "aarch64" ]; then
        ARCH="arm64" 
    else
        echo "   ❌ 不支持的架构: $(uname -m)"
        return 1
    fi
    
    DEB_URL="https://github.com/SagerNet/sing-box/releases/download/${SBOX_VER}/sing-box_1.10.7_linux_${ARCH}.deb"
    
    echo "   - 尝试方式 2: GitHub 直接下载 (${DEB_URL})..."
    rm -f /tmp/sing-box.deb
    if wget -O /tmp/sing-box.deb "$DEB_URL" >/dev/null 2>&1; then
        dpkg -i /tmp/sing-box.deb >/dev/null 2>&1
        echo "   ✅ GitHub包安装成功!"
        rm -f /tmp/sing-box.deb
        return 0
    fi
    echo "   ⚠️ 方式 2 失败 (可能是网络连通性差), 尝试手动代理源..."

    # 尝试3: 使用 ghproxy 极速源
    PROXY_URL="https://ghfast.top/${DEB_URL}"
    echo "   - 尝试方式 3: 加速代理源 (${PROXY_URL})..."
    if wget -O /tmp/sing-box.deb "$PROXY_URL" >/dev/null 2>&1 || curl -L -o /tmp/sing-box.deb "$PROXY_URL" >/dev/null 2>&1; then
        dpkg -i /tmp/sing-box.deb >/dev/null 2>&1
        echo "   ✅ 加速源安装成功!"
        rm -f /tmp/sing-box.deb
        return 0
    fi

    echo "❌ 错误: 所有安装方式均失败，请检查服务器网络是否能访问 GitHub。"
    exit 1
}

echo ">>> [0/8] 深度清理..."
pkill -9 sing-box || true
pkill -9 python3 || true
systemctl stop sbox-web sing-box || true
rm -f /run/sing-box.pid

echo ">>> [1/8] 更新系统..."
apt-get update -q
apt-get install -y curl wget socat openssl ca-certificates python3 python3-venv python3-pip
apt-get install -y python3-flask python3-waitress >/dev/null 2>&1 || true

# 执行增强版安装逻辑
install_singbox

echo ">>> [3/8] 准备目录..."
WORK_DIR="/root/sbox-relay"
mkdir -p "$WORK_DIR/templates"
cd "$WORK_DIR"

KEYS=$(sing-box generate reality-keypair)
PRIVATE_KEY=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
PUBLIC_KEY=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 4)
HOST_IP=$(curl -s ifconfig.me || echo "127.0.0.1")

echo ">>> [5/8] 后端程序..."
cat > "$WORK_DIR/app.py" <<EOF
import json
import os
import subprocess
import uuid
import base64
from flask import Flask, render_template, request, redirect

app = Flask(__name__)
WORK_DIR = "/root/sbox-relay"
DATA_FILE = f"{WORK_DIR}/data.json"
SBOX_CONFIG = "/etc/sing-box/config.json"
START_PORT = 30000 

PRIVATE_KEY = "${PRIVATE_KEY}"
PUBLIC_KEY = "${PUBLIC_KEY}"
SHORT_ID = "${SHORT_ID}"
HOST_IP = "${HOST_IP}"

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def check_service_status():
    status = "unknown"
    logs = ""
    try:
        code = subprocess.call("systemctl is-active --quiet sing-box", shell=True)
        if code == 0:
            status = "running"
        else:
            status = "stopped"
            try: logs = subprocess.check_output("journalctl -u sing-box -n 20 --no-pager", shell=True).decode()
            except: logs = "无法获取日志"
    except: pass
    return status, logs

def update_firewall(base_port, action):
    base_port = int(base_port)
    ports = [base_port, base_port + 1]
    
    has_ufw = run_cmd("command -v ufw")
    has_iptables = run_cmd("command -v iptables")
    
    ufw_active = False
    if has_ufw:
        try:
            if "status: active" in subprocess.check_output("ufw status", shell=True).decode().lower():
                ufw_active = True
        except: pass

    for port in ports:
        if action == "allow":
            if ufw_active:
                run_cmd(f"ufw allow {port}/tcp")
                run_cmd(f"ufw allow {port}/udp")
            elif has_iptables:
                run_cmd(f"iptables -C INPUT -p tcp --dport {port} -j ACCEPT || iptables -I INPUT -p tcp --dport {port} -j ACCEPT")
                run_cmd(f"iptables -C INPUT -p udp --dport {port} -j ACCEPT || iptables -I INPUT -p udp --dport {port} -j ACCEPT")
        elif action == "delete":
            if ufw_active:
                run_cmd(f"ufw delete allow {port}/tcp")
                run_cmd(f"ufw delete allow {port}/udp")
            elif has_iptables:
                run_cmd(f"iptables -D INPUT -p tcp --dport {port} -j ACCEPT")
                run_cmd(f"iptables -D INPUT -p udp --dport {port} -j ACCEPT")
    
    if not ufw_active and has_iptables:
       run_cmd("netfilter-persistent save || service iptables save || true")

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
        "dns": {
            "servers": [{"tag": "google", "address": "8.8.8.8"}, {"tag": "local", "address": "local", "detour": "direct"}]
        },
        "inbounds": [],
        "outbounds": [{"type":"direct","tag":"direct"}, {"type":"block","tag":"block"}],
        "route": {"rules": [], "final": "direct"}
    }
    
    for rule in rules:
        port_vless = int(rule['port'])
        port_socks = port_vless + 1
        
        in_tag_vless = f"in_vless_{port_vless}"
        in_tag_socks = f"in_sock_{port_socks}"
        out_tag = f"out_{port_vless}"

        # 1. VLESS (0.0.0.0 IPv4)
        config['inbounds'].append({
            "type": "vless",
            "tag": in_tag_vless,
            "listen": "0.0.0.0",
            "listen_port": port_vless,
            "users": [{"uuid": rule['uuid'], "flow": "xtls-rprx-vision"}],
            "tls": {
                "enabled": True, "server_name": "www.microsoft.com",
                "reality": {"enabled": True, "handshake":{"server":"www.microsoft.com","server_port":443},"private_key":PRIVATE_KEY,"short_id":[SHORT_ID]}
            }
        })
        
        # 2. Socks5 入站 (0.0.0.0 IPv4)
        config['inbounds'].append({
            "type": "socks",
            "tag": in_tag_socks,
            "listen": "0.0.0.0",
            "listen_port": port_socks
        })

        # 3. 出站
        outbound = {
            "type": "socks", "tag": out_tag, "server": rule['s_ip'], "server_port": int(rule['s_port'])
        }
        if rule.get('s_user'):
            outbound['username'] = rule['s_user']; outbound['password'] = rule['s_pass']
        config['outbounds'].insert(0, outbound)

        # 4. 路由
        config['route']['rules'].insert(0, {
            "inbound": [in_tag_vless, in_tag_socks], "outbound": out_tag
        })

    with open(SBOX_CONFIG, 'w') as f: json.dump(config, f, indent=2)
    run_cmd("systemctl reload sing-box || systemctl restart sing-box")

def parse_link(link):
    link = link.strip()
    if not link.startswith("socks5://"):
        try:
            padded = link + "=" * (-len(link) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
            if decoded.startswith("socks5://"): link = decoded
        except: pass

    content = link.replace("socks5://", "")
    user = ""
    password = ""
    host = ""
    port = ""
    if "@" in content:
        auth_part, host_part = content.split("@", 1)
        if ":" in auth_part: user, password = auth_part.split(":", 1)
        else: user = auth_part
    else: host_part = content
    if "#" in host_part: host_part = host_part.split("#")[0] 
    if ":" in host_part: host, port_str = host_part.split(":", 1)
    else: raise ValueError("无效端口") 
    return {"s_ip": host, "s_port": int(port_str), "s_user": user, "s_pass": password}

def get_next_port(rules):
    used_ports = [int(r['port']) for r in rules]
    candidate = START_PORT
    while candidate in used_ports: candidate += 2 
    return candidate

@app.route('/')
def index():
    rules = load_data()
    try: current_ip = subprocess.check_output("curl -s ifconfig.me", shell=True).decode().strip()
    except: current_ip = HOST_IP

    for r in rules:
        r['link_vless'] = f"vless://{r['uuid']}@{current_ip}:{r['port']}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={PUBLIC_KEY}&sid={SHORT_ID}#{r['remark']}"
        r['socks_port'] = int(r['port']) + 1
        r['link_socks'] = f"socks5://{current_ip}:{r['socks_port']}#{r['remark']}_NoAuth"
    
    svc_status, svc_logs = check_service_status()
    if not rules and svc_status != 'running' and not os.path.exists(SBOX_CONFIG):
         generate_sbox_config([])
         svc_status, svc_logs = check_service_status()

    return render_template('index.html', rules=rules, server_ip=current_ip, svc_status=svc_status, svc_logs=svc_logs)

@app.route('/test/<id>')
def diagnostics(id):
    rules = load_data()
    r = next((x for x in rules if x['id'] == id), None)
    if not r: return "Rule not found"
    local_socks_port = int(r['port']) + 1
    # 诊断命令
    cmd = f"curl -x socks5h://127.0.0.1:{local_socks_port} -I https://www.google.com --connect-timeout 3"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
        if "200" in output or "301" in output or "302" in output:
            return f"✅ 自检成功! <br>如果要从外面连，请找云服务商放行端口 {local_socks_port}"
        else:
            return f"⚠️ 自检失败: <br>{output}"
    except subprocess.CalledProcessError as e:
        return f"❌ 严重错误: {e.output.decode()}"

@app.route('/add', methods=['POST'])
def add():
    rules = load_data()
    try:
        remark = request.form.get('remark')
        sub_link = request.form.get('sub_link')
        info = parse_link(sub_link)
        port = get_next_port(rules)
        new_rule = {
            "id": str(uuid.uuid4())[:8], "remark": remark, "port": port, "uuid": str(uuid.uuid4()),
            "s_ip": info['s_ip'], "s_port": info['s_port'], "s_user": info['s_user'], "s_pass": info['s_pass']
        }
        update_firewall(port, "allow")
        rules.append(new_rule)
        save_data(rules)
        generate_sbox_config(rules)
    except Exception as e:
        return f"Error: {str(e)}", 400
    return redirect('/')

@app.route('/del/<id>')
def delete(id):
    rules = load_data()
    target = next((r for r in rules if r['id'] == id), None)
    if target:
        update_firewall(target['port'], "delete")
        rules = [r for r in rules if r['id'] != id]
        save_data(rules)
        generate_sbox_config(rules)
    return redirect('/')

@app.route('/restart')
def restart_svc():
    run_cmd("systemctl restart sing-box")
    return redirect('/')

if __name__ == '__main__':
    from waitress import serve
    if os.path.exists(DATA_FILE):
        generate_sbox_config(load_data())
    serve(app, host='0.0.0.0', port=5000)
EOF

echo ">>> [5.5/8] Python依赖..."
python3 -c "import flask, waitress" >/dev/null 2>&1 || {
  python3 -m venv "$WORK_DIR/venv"
  "$WORK_DIR/venv/bin/pip" -q install -U pip
  "$WORK_DIR/venv/bin/pip" -q install flask waitress
}

echo ">>> [6/8] 前端..."
# 使用相同的 HTML 模板，不再赘述，保持与 v2.4 一致
cat > "$WORK_DIR/templates/index.html" <<'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Socks5 中转面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body{background:#f4f6f9;font-family:sans-serif;}.card{border:none;border-radius:10px;box-shadow:0 0 15px rgba(0,0,0,0.05);}
    .link-box { cursor: pointer; background: #fff; font-family: monospace; font-size: 0.85rem; }
    .status-ok { color: green; font-weight: bold; }
    .status-err { color: red; font-weight: bold; }
    </style>
</head>
<body>
<div class="container py-5">
    <div class="card mb-4">
        <div class="card-header bg-white py-3 d-flex justify-content-between align-items-center">
            <h5 class="mb-0">🚀 加速中转面板 (2.5 不死安装版)</h5>
            <div>
                IP: <strong>{{ server_ip }}</strong>
                <span class="mx-2">|</span>
                服务: 
                {% if svc_status == 'running' %}
                <span class="status-ok">运行中 ✅</span>
                {% else %}
                <span class="status-err">已停止 ❌</span>
                <a href="/restart" class="btn btn-sm btn-outline-warning ms-2">重启</a>
                {% endif %}
            </div>
        </div>
        
        {% if svc_status != 'running' %}
        <div class="alert alert-danger m-3">
            <strong>服务未响应 ({{svc_status}})</strong>
            <pre class="mt-2 bg-light p-2 border rounded" style="max-height: 200px; overflow:auto;">{{ svc_logs }}</pre>
        </div>
        {% endif %}

        <div class="card-body p-4">
            <form action="/add" method="POST" class="row g-3 mb-4 pb-4 border-bottom">
                <div class="col-md-3">
                    <label class="form-label text-muted small">备注名</label>
                    <input type="text" name="remark" class="form-control" placeholder="例如: 节点A" required>
                </div>
                <div class="col-md-9">
                    <label class="form-label text-muted small">Socks5 订阅链接</label>
                    <input type="text" name="sub_link" class="form-control" placeholder="socks5://..." required>
                </div>
                <div class="col-12 mt-3">
                    <button type="submit" class="btn btn-primary w-100 fw-bold shadow-sm">➕ 新增</button>
                    <div class="small text-muted text-center mt-2">v2.5 多源极速安装 | 30000+ 端口 | 强制 IPv4</div>
                </div>
            </form>

            <div class="table-responsive">
                <table class="table table-hover align-middle">
                    <thead class="table-light">
                        <tr>
                            <th scope="col">备注</th>
                            <th scope="col">出口IP</th>
                            <th scope="col">VLESS (No-Sniff)</th>
                            <th scope="col">Socks5 (No-Auth)</th>
                            <th scope="col" style="width:140px">操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for r in rules %}
                        <tr>
                            <td><span class="badge bg-secondary">{{ r.remark }}</span></td>
                            <td class="small">{{ r.s_ip }}</td>
                            <td>
                                <div class="input-group input-group-sm">
                                    <span class="input-group-text bg-light">:{{ r.port }}</span>
                                    <input type="text" class="form-control link-box text-success" 
                                           value="{{ r.link_vless }}" readonly
                                           onclick="this.select();document.execCommand('copy')">
                                </div>
                            </td>
                            <td>
                                <div class="input-group input-group-sm">
                                    <span class="input-group-text bg-light">:{{ r.socks_port }}</span>
                                    <input type="text" class="form-control link-box text-danger" 
                                           value="{{ r.link_socks }}" readonly
                                           onclick="this.select();document.execCommand('copy')">
                                </div>
                            </td>
                            <td>
                                <a href="/test/{{ r.id }}" target="_blank" class="btn btn-outline-info btn-sm">自检</a>
                                <a href="/del/{{ r.id }}" class="btn btn-outline-danger btn-sm">退订</a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
</body>
</html>
HTML_EOF

echo ">>> [7/8] 系统服务..."
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
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /etc/systemd/system/sing-box.service.d
cat > /etc/systemd/system/sing-box.service.d/override.conf <<EOF
[Service]
User=root
Group=root
StartLimitIntervalSec=0
EOF

touch /var/log/sing-box.log
chmod 666 /var/log/sing-box.log || true

echo ">>> [8/8] 放行端口..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
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
echo "✅ 2.5 不死安装版安装成功！"
echo "♻️  已自动修复 curl TLS 报错"
echo "📂 后台地址: http://${IP}:5000"
echo "=========================================================="
