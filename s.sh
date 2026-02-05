#!/usr/bin/env bash
set -euo pipefail

### ========= 基本配置（可改） =========
WORK_DIR="/root/sbox-relay"
PANEL_PORT="5000"
SBOX_CONFIG="/etc/sing-box/config.json"
LOG_FILE="/var/log/sbox-panel.log"
SBOX_LOG="/var/log/sing-box.log"
### ===================================

_red(){ echo -e "\033[31m$*\033[0m"; }
_grn(){ echo -e "\033[32m$*\033[0m"; }
_ylw(){ echo -e "\033[33m$*\033[0m"; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    _red "请用 root 运行：sudo -i 后再执行"
    exit 1
  fi
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
  else
    OS_ID="unknown"
  fi
  case "$OS_ID" in
    ubuntu|debian) ;;
    *)
      _ylw "未识别系统为 Debian/Ubuntu（检测到: $OS_ID），仍尝试继续安装。"
      ;;
  esac
}

install_deps() {
  _grn ">>> [1/9] 更新系统并安装依赖..."
  apt-get update -q
  apt-get install -y --no-install-recommends \
    python3 python3-pip \
    curl wget ca-certificates \
    openssl \
    socat \
    jq
  pip3 install --upgrade pip >/dev/null
  pip3 install flask gunicorn >/dev/null
}

install_singbox() {
  _grn ">>> [2/9] 安装 Sing-box..."
  if command -v sing-box >/dev/null 2>&1; then
    _ylw "Sing-box 已存在，跳过安装。"
    return
  fi
  bash <(curl -fsSL https://sing-box.app/deb-install.sh)
}

get_public_ip() {
  # 多源兜底
  HOST_IP="$(curl -fsS ifconfig.me 2>/dev/null || true)"
  [[ -n "${HOST_IP}" ]] || HOST_IP="$(curl -fsS api.ipify.org 2>/dev/null || true)"
  [[ -n "${HOST_IP}" ]] || HOST_IP="127.0.0.1"
}

gen_reality_keys() {
  _grn ">>> [3/9] 生成 Reality 密钥..."
  KEYS="$(sing-box generate reality-keypair)"
  PRIVATE_KEY="$(echo "$KEYS" | awk '/PrivateKey/ {print $2}')"
  PUBLIC_KEY="$(echo "$KEYS"  | awk '/PublicKey/  {print $2}')"
  SHORT_ID="$(openssl rand -hex 4)"
  get_public_ip

  _grn "   - 公钥(PBK): $PUBLIC_KEY"
  _grn "   - ShortID  : $SHORT_ID"
  _grn "   - 服务器IP : $HOST_IP"
}

setup_dirs() {
  _grn ">>> [4/9] 创建目录..."
  mkdir -p "$WORK_DIR/templates"
  mkdir -p /var/log
  touch "$SBOX_LOG" "$LOG_FILE"
}

gen_panel_creds() {
  _grn ">>> [5/9] 生成面板账号密码..."
  CREDS_FILE="$WORK_DIR/credentials.txt"
  if [[ -f "$CREDS_FILE" ]]; then
    _ylw "检测到已有面板账号密码：$CREDS_FILE（将复用）"
    PANEL_USER="$(awk -F': ' '/Username/ {print $2}' "$CREDS_FILE" || true)"
    PANEL_PASS="$(awk -F': ' '/Password/ {print $2}' "$CREDS_FILE" || true)"
    [[ -n "$PANEL_USER" && -n "$PANEL_PASS" ]] || {
      PANEL_USER="admin"
      PANEL_PASS="$(openssl rand -base64 18 | tr -d '=+/ ' | head -c 16)"
      cat > "$CREDS_FILE" <<EOF
Username: $PANEL_USER
Password: $PANEL_PASS
EOF
      chmod 600 "$CREDS_FILE"
    }
  else
    PANEL_USER="admin"
    PANEL_PASS="$(openssl rand -base64 18 | tr -d '=+/ ' | head -c 16)"
    cat > "$CREDS_FILE" <<EOF
Username: $PANEL_USER
Password: $PANEL_PASS
EOF
    chmod 600 "$CREDS_FILE"
  fi
}

write_app_py() {
  _grn ">>> [6/9] 写入 Flask 面板（带登录）..."
  cat > "$WORK_DIR/app.py" <<EOF
import json
import os
import subprocess
import uuid
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import urlopen

from flask import Flask, render_template, request, redirect, Response

app = Flask(__name__)

WORK_DIR = "${WORK_DIR}"
DATA_FILE = f"{WORK_DIR}/data.json"
SBOX_CONFIG = "${SBOX_CONFIG}"

PRIVATE_KEY = "${PRIVATE_KEY}"
PUBLIC_KEY = "${PUBLIC_KEY}"
SHORT_ID = "${SHORT_ID}"
DEFAULT_IP = "${HOST_IP}"

PANEL_USER = "${PANEL_USER}"
PANEL_PASS = "${PANEL_PASS}"

def check_auth(username, password):
    return username == PANEL_USER and password == PANEL_PASS

def authenticate():
    return Response(
        "Auth required", 401,
        {"WWW-Authenticate": 'Basic realm="Sbox Panel"'}
    )

def requires_auth(f):
    def wrapped(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    wrapped.__name__ = f.__name__
    return wrapped

def empty_data():
    return {"rules": [], "subscriptions": []}

def load_data():
    if not os.path.exists(DATA_FILE):
        return empty_data()
    try:
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
    except:
        return empty_data()

    # 兼容旧格式 list
    if isinstance(data, list):
        return {"rules": data, "subscriptions": []}

    data.setdefault("rules", [])
    data.setdefault("subscriptions", [])
    return data

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def parse_subscription(text: str):
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("socks5://") or line.startswith("socks://"):
            parsed = urlparse(line)
            if not parsed.hostname or not parsed.port:
                continue
            items.append({
                "s_ip": parsed.hostname,
                "s_port": int(parsed.port),
                "s_user": parsed.username or "",
                "s_pass": parsed.password or ""
            })
            continue

        parts = line.split(":")
        if len(parts) < 2:
            continue
        items.append({
            "s_ip": parts[0],
            "s_port": int(parts[1]),
            "s_user": parts[2] if len(parts) > 2 else "",
            "s_pass": parts[3] if len(parts) > 3 else ""
        })
    return items

def fetch_subscription(url: str):
    with urlopen(url, timeout=12) as resp:
        content = resp.read().decode("utf-8", errors="ignore")
    return parse_subscription(content)

def sync_subscription(sub, data):
    parsed = fetch_subscription(sub["url"])
    base_port = int(sub["base_port"])
    source_tag = f"sub:{sub['id']}"

    # 清掉旧订阅导入的 rules
    data["rules"] = [r for r in data["rules"] if r.get("source") != source_tag]

    for index, item in enumerate(parsed):
        data["rules"].append({
            "id": str(uuid.uuid4())[:8],
            "remark": f"{sub['remark']}-{index + 1}",
            "port": base_port + index,
            "uuid": str(uuid.uuid4()),
            "s_ip": item["s_ip"],
            "s_port": item["s_port"],
            "s_user": item.get("s_user", ""),
            "s_pass": item.get("s_pass", ""),
            "source": source_tag
        })
    sub["last_sync"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    sub["count"] = len(parsed)

def generate_sbox_config(rules):
    config = {
        "log": {"level": "info", "output": "${SBOX_LOG}"},
        "inbounds": [],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {"rules": [], "final": "direct"}
    }

    # 为每条 rule 创建 inbound/outbound/route 绑定
    for rule in rules:
        in_tag = f"in_{rule['port']}"
        out_tag = f"out_{rule['port']}"

        config["inbounds"].append({
            "type": "vless",
            "tag": in_tag,
            "listen": "::",
            "listen_port": int(rule["port"]),
            "users": [{"uuid": rule["uuid"], "flow": "xtls-rprx-vision"}],
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

        config["outbounds"].insert(0, {
            "type": "socks",
            "tag": out_tag,
            "server": rule["s_ip"],
            "server_port": int(rule["s_port"]),
            "username": rule.get("s_user", ""),
            "password": rule.get("s_pass", "")
        })

        config["route"]["rules"].insert(0, {
            "inbound": [in_tag],
            "outbound": out_tag
        })

    os.makedirs(os.path.dirname(SBOX_CONFIG), exist_ok=True)
    with open(SBOX_CONFIG, "w") as f:
        json.dump(config, f, indent=2)

    os.system("systemctl reload sing-box || systemctl restart sing-box")

def current_ip():
    try:
        return subprocess.check_output("curl -fsS ifconfig.me", shell=True).decode().strip()
    except:
        return DEFAULT_IP

@app.route("/")
@requires_auth
def index():
    data = load_data()
    rules = data["rules"]
    ip = current_ip()

    for r in rules:
        r["link"] = (
            f"vless://{r['uuid']}@{ip}:{r['port']}"
            f"?encryption=none&flow=xtls-rprx-vision"
            f"&security=reality&sni=www.microsoft.com&fp=chrome"
            f"&pbk={PUBLIC_KEY}&sid={SHORT_ID}"
            f"#{r['remark']}"
        )
    return render_template("index.html", rules=rules, subscriptions=data["subscriptions"])

@app.route("/add", methods=["POST"])
@requires_auth
def add():
    data = load_data()
    new_rule = {
        "id": str(uuid.uuid4())[:8],
        "remark": request.form.get("remark", "").strip(),
        "port": int(request.form.get("port")),
        "uuid": str(uuid.uuid4()),
        "s_ip": request.form.get("s_ip", "").strip(),
        "s_port": int(request.form.get("s_port")),
        "s_user": request.form.get("s_user", "").strip(),
        "s_pass": request.form.get("s_pass", "").strip(),
        "source": "manual"
    }
    if not new_rule["remark"] or not new_rule["s_ip"]:
        return "Bad request", 400

    # 端口冲突检查
    if any(r["port"] == new_rule["port"] for r in data["rules"]):
        return "Port already exists", 400

    data["rules"].append(new_rule)
    save_data(data)
    generate_sbox_config(data["rules"])
    return redirect("/")

@app.route("/del/<rid>")
@requires_auth
def delete(rid):
    data = load_data()
    data["rules"] = [r for r in data["rules"] if r["id"] != rid]
    save_data(data)
    generate_sbox_config(data["rules"])
    return redirect("/")

@app.route("/add-sub", methods=["POST"])
@requires_auth
def add_sub():
    data = load_data()
    sub = {
        "id": str(uuid.uuid4())[:8],
        "remark": request.form.get("sub_remark", "").strip(),
        "url": request.form.get("sub_url", "").strip(),
        "base_port": int(request.form.get("sub_base_port")),
        "last_sync": "",
        "count": 0
    }
    if not sub["remark"] or not sub["url"]:
        return "Bad request", 400

    data["subscriptions"].append(sub)
    sync_subscription(sub, data)
    save_data(data)
    generate_sbox_config(data["rules"])
    return redirect("/")

@app.route("/sync/<sid>")
@requires_auth
def sync(sid):
    data = load_data()
    sub = next((s for s in data["subscriptions"] if s["id"] == sid), None)
    if not sub:
        return "Not found", 404
    sync_subscription(sub, data)
    save_data(data)
    generate_sbox_config(data["rules"])
    return redirect("/")

@app.route("/del-sub/<sid>")
@requires_auth
def del_sub(sid):
    data = load_data()
    data["subscriptions"] = [s for s in data["subscriptions"] if s["id"] != sid]
    data["rules"] = [r for r in data["rules"] if r.get("source") != f"sub:{sid}"]
    save_data(data)
    generate_sbox_config(data["rules"])
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=${PANEL_PORT})
EOF
}

write_index_html() {
  _grn ">>> [7/9] 写入前端页面..."
  cat > "$WORK_DIR/templates/index.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
  <title>Socks5 Relay Panel</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{background:#f4f6f9;font-family:sans-serif;}
    .card{border:none;border-radius:10px;box-shadow:0 0 15px rgba(0,0,0,0.05);}
  </style>
</head>
<body>
<div class="container py-5">
  <div class="card">
    <div class="card-header bg-primary text-white text-center py-3">
      <h4 class="mb-0">🚀 Socks5 加速中转面板（VLESS Reality）</h4>
    </div>

    <div class="card-body p-4">
      <form action="/add" method="POST" class="row g-3 mb-4 pb-4 border-bottom">
        <div class="col-md-3">
          <label class="form-label text-muted small">备注名</label>
          <input type="text" name="remark" class="form-control" placeholder="例如: 店铺A" required>
        </div>
        <div class="col-md-2">
          <label class="form-label text-muted small">中转端口(入口)</label>
          <input type="number" name="port" class="form-control" placeholder="20001" required>
        </div>
        <div class="col-md-3">
          <label class="form-label text-muted small">Socks5 IP(目标)</label>
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

      <form action="/add-sub" method="POST" class="row g-3 mb-4 pb-4 border-bottom">
        <div class="col-md-3">
          <label class="form-label text-muted small">订阅名称</label>
          <input type="text" name="sub_remark" class="form-control" placeholder="例如: 住宅订阅A" required>
        </div>
        <div class="col-md-5">
          <label class="form-label text-muted small">订阅链接</label>
          <input type="url" name="sub_url" class="form-control" placeholder="https://example.com/sub.txt" required>
        </div>
        <div class="col-md-2">
          <label class="form-label text-muted small">起始端口</label>
          <input type="number" name="sub_base_port" class="form-control" placeholder="21000" required>
        </div>
        <div class="col-md-2 d-flex align-items-end">
          <button type="submit" class="btn btn-outline-primary w-100 fw-bold">🔄 导入订阅</button>
        </div>
        <div class="col-12">
          <div class="small text-muted">
            订阅格式支持：<code>socks5://user:pass@ip:port</code> 或 <code>ip:port:user:pass</code>（一行一个）
          </div>
        </div>
      </form>

      {% if subscriptions %}
      <div class="table-responsive mb-4">
        <table class="table table-sm table-bordered align-middle">
          <thead class="table-light">
            <tr>
              <th>订阅</th>
              <th>起始端口</th>
              <th>数量</th>
              <th>最后同步</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {% for s in subscriptions %}
            <tr>
              <td class="fw-bold">{{ s.remark }}</td>
              <td>{{ s.base_port }}</td>
              <td>{{ s.count }}</td>
              <td class="text-muted small">{{ s.last_sync or '未同步' }}</td>
              <td>
                <a href="/sync/{{ s.id }}" class="btn btn-outline-secondary btn-sm">同步</a>
                <a href="/del-sub/{{ s.id }}" class="btn btn-outline-danger btn-sm">删除</a>
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% endif %}

      <div class="table-responsive">
        <table class="table table-hover align-middle">
          <thead class="table-light">
            <tr>
              <th>备注</th>
              <th>中转端口</th>
              <th>目标 IP</th>
              <th style="width:40%;">VLESS 链接（点击复制）</th>
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
                <input type="text" class="form-control form-control-sm bg-white"
                       value="{{ r.link }}"
                       onclick="this.select();document.execCommand('copy');this.classList.add('is-valid');"
                       readonly>
              </td>
              <td><a href="/del/{{ r.id }}" class="btn btn-outline-danger btn-sm">删除</a></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

    </div>

    <div class="card-footer text-center text-muted small bg-white py-3">
      面板端口：5000（已启用 Basic Auth 登录）| Sing-box 日志：/var/log/sing-box.log
    </div>
  </div>
</div>
</body>
</html>
HTML
}

write_systemd() {
  _grn ">>> [8/9] 写入 systemd 服务..."

  # sbox-panel: gunicorn 托管 flask
  cat > /etc/systemd/system/sbox-panel.service <<EOF
[Unit]
Description=Sbox Relay Panel (Flask/Gunicorn)
After=network.target

[Service]
Type=simple
WorkingDirectory=${WORK_DIR}
ExecStart=/usr/bin/gunicorn -w 2 -b 0.0.0.0:${PANEL_PORT} app:app
Restart=always
RestartSec=2
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable sing-box >/dev/null 2>&1 || true
  systemctl enable sbox-panel >/dev/null 2>&1

  systemctl restart sing-box || true
  systemctl restart sbox-panel
}

final_print() {
  _grn ">>> [9/9] 完成 ✅"
  get_public_ip

  echo
  _grn "================= 面板信息 ================="
  _grn "面板地址:  http://${HOST_IP}:${PANEL_PORT}/"
  _grn "账号:      ${PANEL_USER}"
  _grn "密码:      ${PANEL_PASS}"
  _grn "凭据文件:  ${WORK_DIR}/credentials.txt"
  echo
  _grn "================ Reality 信息 ==============="
  _grn "PublicKey: ${PUBLIC_KEY}"
  _grn "ShortID:   ${SHORT_ID}"
  echo
  _grn "================ 服务状态 ==================="
  systemctl is-active --quiet sing-box && _grn "sing-box:   active" || _ylw "sing-box:   not active"
  systemctl is-active --quiet sbox-panel && _grn "sbox-panel: active" || _ylw "sbox-panel: not active"
  echo
  _ylw "日志："
  _ylw "  sing-box:   ${SBOX_LOG}"
  _ylw "  sbox-panel: ${LOG_FILE}"
  echo
}

main() {
  require_root
  detect_os
  install_deps
  install_singbox
  setup_dirs
  gen_reality_keys
  gen_panel_creds
  write_app_py
  write_index_html
  write_systemd
  final_print
}

main "$@"
