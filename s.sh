#!/bin/bash
set -e

# ==========================================
# Socks5 转 VLESS 极简中转面板 (v3.4 链接优化版)
# 变更日志:
# 3.4: 修复 [本机直连] 端口在未设置密码时不启动的 Bug (users: [])
#      优化一键安装体验
# 3.3: 密钥固化 (升级不换号)
# 3.2: 本机直连节点 (10086/10087)
# ==========================================

sed -i 's/\r$//' "$0" 2>/dev/null || true

if [ "$EUID" -ne 0 ]; then
  echo "❌ 错误: 请使用 'sudo -i' 切换到 root 用户后再运行此脚本！"
  exit 1
fi

LOG_FILE="/var/log/sing-box-install.log"

install_singbox() {
    echo ">>> [2/8] 正在安装 Sing-box..."
    if bash <(curl -fsSL https://sing-box.app/deb-install.sh) >/dev/null 2>&1; then return 0; fi
    SBOX_VER="v1.10.7"
    if [ "$(uname -m)" = "x86_64" ]; then ARCH="amd64"; elif [ "$(uname -m)" = "aarch64" ]; then ARCH="arm64"; else return 1; fi
    DEB_URL="https://github.com/SagerNet/sing-box/releases/download/${SBOX_VER}/sing-box_1.10.7_linux_${ARCH}.deb"
    rm -f /tmp/sing-box.deb
    if wget -O /tmp/sing-box.deb "$DEB_URL" >/dev/null 2>&1 || wget -O /tmp/sing-box.deb "https://ghfast.top/${DEB_URL}" >/dev/null 2>&1; then
        dpkg -i /tmp/sing-box.deb >/dev/null 2>&1
        rm -f /tmp/sing-box.deb
        return 0
    fi
    return 1
}

echo ">>> [0/8] 深度清理..."
systemctl stop sbox-web sing-box || true

echo ">>> [1/8] 更新系统..."
apt-get update -q
apt-get install -y curl wget socat openssl ca-certificates python3 python3-venv python3-pip net-tools
apt-get install -y python3-flask python3-waitress >/dev/null 2>&1 || true

install_singbox || { echo "❌ Sing-box 安装失败"; exit 1; }

echo ">>> [3/8] 准备目录与密钥..."
WORK_DIR="/root/sbox-relay"
mkdir -p "$WORK_DIR/templates"
cd "$WORK_DIR"

KEY_FILE="$WORK_DIR/keys.conf"
if [ -f "$KEY_FILE" ]; then
    echo "   ♻️  检测到旧密钥，正在恢复..."
    source "$KEY_FILE"
else
    echo "   🆕 生成新密钥..."
    KEYS=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    SHORT_ID=$(openssl rand -hex 4)
    echo "PRIVATE_KEY=\"$PRIVATE_KEY\"" > "$KEY_FILE"
    echo "PUBLIC_KEY=\"$PUBLIC_KEY\"" >> "$KEY_FILE"
    echo "SHORT_ID=\"$SHORT_ID\"" >> "$KEY_FILE"
fi
HOST_IP=$(curl -s ifconfig.me || echo "127.0.0.1")

echo ">>> [5/8] 后端程序..."
cat > "$WORK_DIR/app.py" <<EOF
import json
import os
import subprocess
import uuid
import base64
import secrets
import urllib.parse
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
WORK_DIR = "/root/sbox-relay"
DATA_FILE = f"{WORK_DIR}/data.json"
ADMIN_FILE = f"{WORK_DIR}/admin.json"
SBOX_CONFIG = "/etc/sing-box/config.json"
START_PORT = 30000 
LOCAL_VLESS_PORT = 10086
LOCAL_SOCKS_PORT = 10087

PRIVATE_KEY = "${PRIVATE_KEY}"
PUBLIC_KEY = "${PUBLIC_KEY}"
SHORT_ID = "${SHORT_ID}"
HOST_IP = "${HOST_IP}"

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except: return False

def load_admin():
    if not os.path.exists(ADMIN_FILE): return None
    try:
        with open(ADMIN_FILE, 'r') as f: 
            data = json.load(f)
            if 'system_uuid' not in data:
                data['system_uuid'] = str(uuid.uuid4())
                with open(ADMIN_FILE, 'w') as fw: json.dump(data, fw)
            return data
    except: return None

def save_admin(username, password):
    curr = load_admin()
    sys_uuid = curr['system_uuid'] if curr else str(uuid.uuid4())
    with open(ADMIN_FILE, 'w') as f:
        json.dump({"username": username, "password": password, "system_uuid": sys_uuid}, f)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = load_admin()
        if not admin: return redirect(url_for('setup'))
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if load_admin(): return redirect(url_for('login'))
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        if user and pwd:
            save_admin(user, pwd)
            update_firewall(0, "local_init")
            generate_sbox_config(load_data())
            session['logged_in'] = True
            return redirect('/')
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not load_admin(): return redirect(url_for('setup'))
    error = None
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        admin = load_admin()
        if u == admin['username'] and p == admin['password']:
            session['logged_in'] = True; session.permanent = True
            return redirect('/')
        else:
            time.sleep(2); error = "账号或密码错误"
    return render_template('login.html', error=error)

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    admin = load_admin()
    if admin['password'] != request.form.get('old_password'): return "密码错误", 400
    save_admin(admin['username'], request.form.get('new_password'))
    generate_sbox_config(load_data())
    return redirect('/')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

def check_service_status():
    status = "stopped"; logs = ""
    try:
        if subprocess.call("systemctl is-active --quiet sing-box", shell=True) == 0: status = "running"
        logs = subprocess.check_output("journalctl -u sing-box -n 20 --no-pager", shell=True).decode()
    except: pass
    return status, logs

def update_firewall(base_port, action):
    ports = [LOCAL_VLESS_PORT, LOCAL_SOCKS_PORT] if action == "local_init" else [int(base_port), int(base_port)+1]
    if action == "local_init": action = "allow"
    
    has_ufw = run_cmd("command -v ufw")
    ufw_active = False
    if has_ufw:
        try:
           if "status: active" in subprocess.check_output("ufw status", shell=True).decode().lower(): ufw_active = True
        except: pass

    for port in ports:
        if action == "allow":
            if ufw_active: run_cmd(f"ufw allow {port}/tcp"); run_cmd(f"ufw allow {port}/udp")
            else:
                run_cmd(f"iptables -C INPUT -p tcp --dport {port} -j ACCEPT || iptables -I INPUT -p tcp --dport {port} -j ACCEPT")
                run_cmd(f"iptables -C INPUT -p udp --dport {port} -j ACCEPT || iptables -I INPUT -p udp --dport {port} -j ACCEPT")
        else:
            if ufw_active: run_cmd(f"ufw delete allow {port}/tcp"); run_cmd(f"ufw delete allow {port}/udp")
            else:
                run_cmd(f"iptables -D INPUT -p tcp --dport {port} -j ACCEPT")
                run_cmd(f"iptables -D INPUT -p udp --dport {port} -j ACCEPT")
    if not ufw_active: run_cmd("netfilter-persistent save 2>/dev/null || service iptables save 2>/dev/null || true")

def load_data():
    if not os.path.exists(DATA_FILE): return []
    try:
        with open(DATA_FILE, 'r') as f: return json.load(f)
    except: return []

def save_data(data):
    with open(DATA_FILE, 'w') as f: json.dump(data, f, indent=2)

def generate_sbox_config(rules):
    admin = load_admin()
    socks_users = [{"username": admin['username'], "password": admin['password']}] if admin else []
    sys_uuid = admin['system_uuid'] if admin else str(uuid.uuid4())

    config = {
        "log": {"level": "info", "output": "/var/log/sing-box.log"},
        "dns": {"servers": [{"tag": "google", "address": "8.8.8.8"}, {"tag": "local", "address": "local", "detour": "direct"}]},
        "inbounds": [
            {"type": "socks", "tag": "keep_alive", "listen": "127.0.0.1", "listen_port": 64000},
            {"type": "vless", "tag": "local_vless", "listen": "0.0.0.0", "listen_port": LOCAL_VLESS_PORT, "users": [{"uuid": sys_uuid, "flow": "xtls-rprx-vision"}], "tls": {"enabled": True, "server_name": "www.microsoft.com", "reality": {"enabled": True, "handshake":{"server":"www.microsoft.com","server_port":443},"private_key":PRIVATE_KEY,"short_id":[SHORT_ID]}}},
        ],
        "outbounds": [{"type":"direct","tag":"direct"}, {"type":"block","tag":"block"}],
        "route": {"rules": [{"inbound": ["local_vless", "local_socks"], "outbound": "direct"}], "final": "direct"}
    }

    # v3.4 Fix: 本机 Socks5 -- 如果没用户(未初始化)则无Auth，如果有则Auth
    # 避免由空列表导致的报错
    local_socks_in = {"type": "socks", "tag": "local_socks", "listen": "0.0.0.0", "listen_port": LOCAL_SOCKS_PORT}
    if socks_users: local_socks_in["users"] = socks_users
    config["inbounds"].append(local_socks_in)
    
    for rule in rules:
        pv = int(rule['port']); ps = pv + 1
        # Inbounds
        config['inbounds'].append({"type": "vless", "tag": f"in_vl_{pv}", "listen": "0.0.0.0", "listen_port": pv, "users": [{"uuid": rule['uuid'], "flow": "xtls-rprx-vision"}], "tls": {"enabled": True, "server_name": "www.microsoft.com", "reality": {"enabled": True, "handshake":{"server":"www.microsoft.com","server_port":443},"private_key":PRIVATE_KEY,"short_id":[SHORT_ID]}}})
        sb_in = {"type": "socks", "tag": f"in_sk_{ps}", "listen": "0.0.0.0", "listen_port": ps}; 
        if socks_users: sb_in["users"] = socks_users
        config['inbounds'].append(sb_in)
        
        # Outbounds
        otyp = rule.get('type', 'socks')
        out = {"tag": f"out_{pv}"}
        
        if otyp == 'vless':
            out.update({"type": "vless", "server": rule.get('server', rule.get('s_ip')), "server_port": int(rule.get('server_port', rule.get('s_port'))), "uuid": rule.get('uuid_remote'), "flow": rule.get('flow','')})
            if rule.get('security') == 'reality':
                out['tls'] = {"enabled": True, "server_name": rule.get('sni'), "utls": {"enabled": True, "fingerprint": rule.get('fp', 'chrome')}, "reality": {"enabled": True, "public_key": rule.get('pbk'), "short_id": rule.get('sid', '')}}
            elif rule.get('security') == 'tls':
                out['tls'] = {"enabled": True, "server_name": rule.get('sni'), "insecure": True}

        elif otyp == 'hysteria2':
            out.update({"type": "hysteria2", "server": rule.get('server', rule.get('s_ip')), "server_port": int(rule.get('server_port', rule.get('s_port'))), "password": rule.get('password',''), "tls": {"enabled": True, "server_name": rule.get('sni', rule.get('server', rule.get('s_ip'))), "insecure": rule.get('insecure', False)}})
            if rule.get('obfs'): out['obfs'] = {"type": "salamander", "password": rule.get('obfs_password')}

        elif otyp == 'vmess':
            out.update({"type": "vmess", "server": rule.get('server'), "server_port": int(rule.get('server_port')), "uuid": rule.get('uuid_remote'), "security": rule.get('security', 'auto'), "alter_id": int(rule.get('alter_id', 0))})
            transport = {"type": rule.get('net', 'tcp')}
            if rule.get('net') == 'ws':
                transport['path'] = rule.get('path', '/')
                if rule.get('host'): transport['headers'] = {'Host': rule.get('host')}
            elif rule.get('net') == 'grpc':
                transport['service_name'] = rule.get('path', '')
            out['transport'] = transport
            if rule.get('tls') == 'tls':
                out['tls'] = {"enabled": True, "server_name": rule.get('sni', rule.get('host', rule.get('server'))), "insecure": True}

        else: # socks
            out.update({"type": "socks", "server": rule['s_ip'], "server_port": int(rule['s_port']), "username": rule.get('s_user',''), "password": rule.get('s_pass','')})
            
        config['outbounds'].insert(0, out)
        config['route']['rules'].insert(0, {"inbound": [f"in_vl_{pv}", f"in_sk_{ps}"], "outbound": f"out_{pv}"})

    with open(SBOX_CONFIG, 'w') as f: json.dump(config, f, indent=2)
    run_cmd("systemctl reload sing-box || systemctl restart sing-box")

# ... (rest same as v3.3) ...
def parse_link(link):
    link = link.strip(); 
    if not link: raise Exception("为空")
    if "://" not in link:
        try: link = base64.urlsafe_b64decode(link+"="*(-len(link)%4)).decode()
        except: pass
    
    u = urllib.parse.urlparse(link); scheme = u.scheme.lower()
    base = {"s_ip": u.hostname, "s_port": u.port, "server": u.hostname, "server_port": u.port}
    
    if scheme == 'socks5':
        base.update({"type": "socks", "s_user": u.username or "", "s_pass": u.password or ""})
        return base
    elif scheme == 'vless':
        q = urllib.parse.parse_qs(u.query)
        base.update({"type": "vless", "uuid_remote": u.username, "flow": q.get('flow',[''])[0], "security": q.get('security',[''])[0], "sni": q.get('sni',[''])[0], "fp": q.get('fp',['chrome'])[0], "pbk": q.get('pbk',[''])[0], "sid": q.get('sid',[''])[0]})
        return base
    elif scheme == 'hy2' or scheme == 'hysteria2':
        q = urllib.parse.parse_qs(u.query)
        base.update({"type": "hysteria2", "password": u.username or "", "sni": q.get('sni', [u.hostname])[0], "insecure": q.get('insecure',['0'])[0]=='1', "obfs": q.get('obfs',[''])[0], "obfs_password": q.get('obfs-password',[''])[0]})
        return base
    elif scheme == 'vmess':
        try:
            b64 = link.replace("vmess://", "")
            js = json.loads(base64.urlsafe_b64decode(b64+"="*(-len(b64)%4)).decode())
            base.update({
                "type": "vmess", "server": js.get('add'), "server_port": js.get('port'), "s_ip": js.get('add'), "s_port": js.get('port'),
                "uuid_remote": js.get('id'), "alter_id": js.get('aid', 0), "security": js.get('scy', 'auto'),
                "net": js.get('net', 'tcp'), "type_header": js.get('type', 'none'),
                "host": js.get('host', ''), "path": js.get('path', ''), "tls": js.get('tls', ''), "sni": js.get('sni', '')
            })
            return base
        except Exception as e: raise Exception(f"VMess解析失败: {str(e)}")
    else: raise Exception("不支持协议 "+scheme)

def get_next_port(rules):
    used = [int(r['port']) for r in rules]
    c = START_PORT; 
    while c in used: c += 2 
    return c

@app.route('/')
@login_required 
def index():
    rules = load_data(); admin = load_admin()
    try: cip = subprocess.check_output("curl -s ifconfig.me", shell=True).decode().strip()
    except: cip = HOST_IP
    lv = f"vless://{admin['system_uuid']}@{cip}:{LOCAL_VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={PUBLIC_KEY}&sid={SHORT_ID}#本机直连VLESS"
    ls = f"socks5://{admin['username']}:{admin['password']}@{cip}:{LOCAL_SOCKS_PORT}#本机直连Socks5"
    for r in rules:
        r['link_vless'] = f"vless://{r['uuid']}@{cip}:{r['port']}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={PUBLIC_KEY}&sid={SHORT_ID}#{r['remark']}"
        r['socks_port'] = int(r['port']) + 1
        r['link_socks'] = f"socks5://{admin['username']}:{admin['password']}@{cip}:{r['socks_port']}#{r['remark']}"
    st, lg = check_service_status()
    return render_template('index.html', rules=rules, server_ip=cip, svc_status=st, svc_logs=lg, username=admin['username'], local_vless=lv, local_socks=ls)

@app.route('/test/<id>')
@login_required
def diagnostics(id):
    rules = load_data(); admin = load_admin(); r = next((x for x in rules if x['id'] == id), None)
    if not r: return "Err"
    try:
        o = subprocess.check_output(f"curl -x socks5://{admin['username']}:{admin['password']}@127.0.0.1:{int(r['port'])+1} -I https://www.google.com --connect-timeout 3", shell=True, stderr=subprocess.STDOUT).decode()
        if "200" in o or "301" in o: return "✅ 通!"
        return f"⚠️ 失败: {o}"
    except Exception as e: return f"❌ {e}"

@app.route('/add', methods=['POST'])
@login_required
def add():
    rules = load_data()
    try:
        i = parse_link(request.form.get('sub_link')); p = get_next_port(rules); update_firewall(p, "allow")
        rules.append({"id": str(uuid.uuid4())[:8], "remark": request.form.get('remark'), "port": p, "uuid": str(uuid.uuid4()), **i})
        save_data(rules); generate_sbox_config(rules)
    except Exception as e: return f"{e}", 400
    return redirect('/')

@app.route('/del/<id>')
@login_required
def delete(id):
    r = load_data(); t = next((x for x in r if x['id'] == id), None)
    if t: update_firewall(t['port'], "delete"); r = [x for x in r if x['id'] != id]; save_data(r); generate_sbox_config(r)
    return redirect('/')

if __name__ == '__main__':
    from waitress import serve
    update_firewall(0, "local_init")
    generate_sbox_config(load_data()) 
    serve(app, host='0.0.0.0', port=5000)
EOF

echo ">>> [6/8] 前端页面 (使用 v3.2 模板)..."
cat > "$WORK_DIR/templates/setup.html" <<'HTML_EOF'
<!DOCTYPE html><html><head><title>初始化</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>body{background:#f4f6f9;display:flex;align-items:center;justify-content:center;height:100vh}</style></head><body><div class="card shadow p-4" style="width:400px"><h3 class="text-center mb-3">🛠️ 初始化</h3><form action="/setup" method="POST"><div class="mb-3"><label>用户名</label><input type="text" name="username" class="form-control" placeholder="admin" required></div><div class="mb-3"><label>密码</label><input type="password" name="password" class="form-control" required></div><button type="submit" class="btn btn-primary w-100">启动</button></form></div></body></html>
HTML_EOF
cat > "$WORK_DIR/templates/login.html" <<'HTML_EOF'
<!DOCTYPE html><html><head><title>登录</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>body{background:#f4f6f9;display:flex;align-items:center;justify-content:center;height:100vh}</style></head><body><div class="card shadow p-4" style="width:400px"><h3 class="text-center mb-3">🔐 登录</h3>{% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}<form action="/login" method="POST"><div class="mb-3"><label>用户名</label><input type="text" name="username" class="form-control" required></div><div class="mb-3"><label>密码</label><input type="password" name="password" class="form-control" required></div><button type="submit" class="btn btn-success w-100">登录</button></form></div></body></html>
HTML_EOF
cat > "$WORK_DIR/templates/index.html" <<'HTML_EOF'
<!DOCTYPE html><html><head><title>中转面板</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script><style>body{background:#f4f6f9;}.status-ok{color:green}.status-err{color:red}</style></head>
<body><div class="container py-5"><div class="card shadow mb-4"><div class="card-header bg-white"><h5 class="mb-0">🏠 本机直连节点</h5></div><div class="card-body"><div class="row g-3"><div class="col-md-6"><label class="small text-muted">VLESS (端口 10086)</label><div class="input-group input-group-sm"><input type="text" class="form-control text-success fw-bold" value="{{ local_vless }}" readonly onclick="this.select();document.execCommand('copy')"><button class="btn btn-outline-secondary" onclick="this.previousElementSibling.click()">复制</button></div></div><div class="col-md-6"><label class="small text-muted">Socks5 (端口 10087)</label><div class="input-group input-group-sm"><input type="text" class="form-control text-primary fw-bold" value="{{ local_socks }}" readonly onclick="this.select();document.execCommand('copy')"><button class="btn btn-outline-secondary" onclick="this.previousElementSibling.click()">复制</button></div></div></div></div></div>
<div class="card shadow"><div class="card-header bg-white py-3 d-flex justify-content-between align-items-center"><h5 class="mb-0">📡 转发规则</h5><div><span class="badge bg-light text-dark border me-2">{{ username }}</span>{% if svc_status == 'running' %}<span class="status-ok fw-bold me-3">运行中 ✅</span>{% else %}<span class="status-err fw-bold me-3">已停止</span>{% endif %}<button class="btn btn-sm btn-outline-primary me-2" data-bs-toggle="modal" data-bs-target="#pwdModal">改密</button><a href="/logout" class="btn btn-sm btn-outline-secondary">退出</a></div></div>
{% if svc_status != 'running' %}<div class="alert alert-danger m-3"><pre class="mb-0">{{ svc_logs }}</pre></div>{% endif %}
<div class="card-body"><form action="/add" method="POST" class="row g-2 mb-4 border-bottom pb-4"><div class="col-md-3"><input type="text" name="remark" class="form-control" placeholder="备注名" required></div><div class="col-md-7"><input type="text" name="sub_link" class="form-control" placeholder="socks5://, vless://, hy2://, vmess://" required></div><div class="col-md-2"><button type="submit" class="btn btn-primary w-100">新增转发</button></div></form>
<table class="table table-hover align-middle"><thead><tr><th>备注</th><th>类型/IP</th><th>转发 VLESS / Socks5</th><th>操作</th></tr></thead><tbody>{% for r in rules %}<tr><td><span class="badge bg-secondary">{{ r.remark }}</span></td><td class="small"><span class="badge bg-info text-dark">{{ r.type|default('socks') }}</span><br>{{ r.s_ip }}</td><td><div class="input-group input-group-sm mb-1"><span class="input-group-text">VL :{{ r.port }}</span><input type="text" class="form-control" value="{{ r.link_vless }}" readonly onclick="this.select();document.execCommand('copy')"></div><div class="input-group input-group-sm"><span class="input-group-text">S5 :{{ r.socks_port }}</span><input type="text" class="form-control" value="{{ r.link_socks }}" readonly onclick="this.select();document.execCommand('copy')"></div></td><td><a href="/test/{{ r.id }}" target="_blank" class="btn btn-outline-info btn-sm">自检</a> <a href="/del/{{ r.id }}" class="btn btn-outline-danger btn-sm">删</a></td></tr>{% endfor %}</tbody></table></div></div></div>
<div class="modal fade" id="pwdModal"><div class="modal-dialog"><div class="modal-content"><form action="/update_password" method="POST"><div class="modal-header"><h5 class="modal-title">修改密码</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div class="mb-3"><label>当前密码</label><input type="password" name="old_password" class="form-control" required></div><div class="mb-3"><label>新密码</label><input type="password" name="new_password" class="form-control" required></div></div><div class="modal-footer"><button type="submit" class="btn btn-primary">确认修改</button></div></form></div></div></div></body></html>
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
touch /var/log/sing-box.log; chmod 666 /var/log/sing-box.log || true

echo ">>> [8/8] 放行端口..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then ufw allow 5000/tcp >/dev/null 2>&1 || true; else if command -v iptables >/dev/null 2>&1; then iptables -C INPUT -p tcp --dport 5000 -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport 5000 -j ACCEPT; fi; fi

systemctl daemon-reload; systemctl enable sbox-web sing-box >/dev/null 2>&1; systemctl restart sbox-web sing-box
IP=$(curl -s ifconfig.me || echo "$HOST_IP")
echo ""; echo "✅ v3.4 链接优化版安装成功！"
echo "🛠️  端口状态:"
netstat -nlp | grep sing-box | awk '{print "    " $4 "\t(PID " $7 ")"}'
echo "👉 您的永久一键脚本命令 (已包含依赖安装): "
echo "apt-get update -y && apt-get install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/saswawa/relay/main/s.sh | tr -d '\r')"
