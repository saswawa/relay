#!/bin/bash
# TKLOCK 中转系统 2.0 自动化脚本

# 1. 环境自愈
echo ">>> 正在安装环境..."
apt-get update -qq && apt-get install -y python3-flask sing-box curl socat >/dev/null 2>&1

# 2. 目录初始化
WORK_DIR="/root/sbox-relay"
mkdir -p "$WORK_DIR/templates"

# 3. 密钥持久化
[ ! -f "$WORK_DIR/k.env" ] && sing-box generate reality-keypair | tee "$WORK_DIR/k.env"
PRI=$(grep "PrivateKey" "$WORK_DIR/k.env" | awk '{print $2}')
PUB=$(grep "PublicKey" "$WORK_DIR/k.env" | awk '{print $2}')
SID=$(openssl rand -hex 4)
IP=$(hostname -I | awk '{print $1}')

# 4. 写入 Python 后端
cat > "$WORK_DIR/app.py" <<PY_EOF
import json, os, uuid
from flask import Flask, render_template, request, redirect
app = Flask(__name__)
D, C = "$WORK_DIR/data.json", "/etc/sing-box/config.json"
def save(r):
    with open(D, 'w') as f: json.dump(r, f)
    cfg = {"log":{"level":"info"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[]}}
    for x in r:
        it, ot = f"in_{x['p']}", f"out_{x['p']}"
        cfg['inbounds'].append({"type":"vless","tag":it,"listen":"::","listen_port":int(x['p']),"users":[{"uuid":x['u'],"flow":"xtls-rprx-vision"}],"tls":{"enabled":True,"server_name":"www.microsoft.com","reality":{"enabled":True,"handshake":{"server":"www.microsoft.com","server_port":443},"private_key":"$PRI","short_id":["$SID"]}}})
        cfg['outbounds'].insert(0,{"type":"socks","tag":ot,"server":x['sip'],"server_port":int(x['sport']),"username":x['suser'],"password":x['spass']})
        cfg['route']['rules'].insert(0,{"inbound":[it],"outbound":ot})
    with open(C, 'w') as f: json.dump(cfg, f)
    os.system("systemctl reload sing-box")
@app.route('/')
def index():
    try: r = json.load(open(D))
    except: r = []
    return render_template('index.html', rules=r, pub="$PUB", sid="$SID", ip="$IP")
@app.route('/add', methods=['POST'])
def add():
    try: r = json.load(open(D))
    except: r = []
    r.append({"id":str(uuid.uuid4())[:8],"rem":request.form.get('rem'),"p":request.form.get('p'),"u":str(uuid.uuid4()),"sip":request.form.get('sip'),"sport":request.form.get('sport'),"suser":request.form.get('suser',''),"spass":request.form.get('spass','')})
    save(r); return redirect('/')
@app.route('/del/<id>')
def delete(id):
    try: r = json.load(open(D))
    except: r = []
    save([x for x in r if x['id'] != id]); return redirect('/')
if __name__ == '__main__': app.run(host='0.0.0.0', port=5000)
PY_EOF

# 5. 写入简易前端
cat > "$WORK_DIR/templates/index.html" <<HTML_EOF
<!DOCTYPE html><html><head><title>Relay</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-light"><div class="container py-5"><h3>🚀 TKLOCK 中转控制台</h3><form action="/add" method="POST" class="row g-2 mb-4">
<div class="col-3"><input name="rem" class="form-control" placeholder="备注" required></div><div class="col-2"><input name="p" class="form-control" placeholder="端口" required></div>
<div class="col-3"><input name="sip" class="form-control" placeholder="S5 IP" required></div><div class="col-2"><input name="sport" class="form-control" placeholder="S5端口" required></div>
<button class="btn btn-primary mt-2">添加</button></form><table class="table"><thead><tr><th>备注</th><th>入口</th><th>链接 (点击复制)</th><th>操作</th></tr></thead>
<tbody>{% for r in rules %}<tr><td>{{r.rem}}</td><td>:{{r.p}}</td><td><input class="form-control form-control-sm" value="vless://{{r.u}}@{{ip}}:{{r.p}}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={{pub}}&sid={{sid}}#{{r.rem}}" onclick="this.select();document.execCommand('copy');" readonly></td><td><a href="/del/{{r.id}}" class="btn btn-danger btn-sm">X</a></td></tr>{% endfor %}
</tbody></table></div></body></html>
HTML_EOF

# 6. 服务自启配置
sed -i 's/User=sing-box/User=root/g' /lib/systemd/system/sing-box.service
cat > /etc/systemd/system/sbox-web.service <<EOF
[Unit]
Description=Sbox Web
After=network.target
[Service]
User=root
WorkingDirectory=$WORK_DIR
ExecStart=/usr/bin/python3 app.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# 7. 强制启动
systemctl daemon-reload
systemctl enable sbox-web sing-box >/dev/null 2>&1
systemctl restart sbox-web sing-box
iptables -F
echo "✅ 安装成功！访问: http://$IP:5000"