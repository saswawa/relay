一键脚本：
```bash
apt-get update -y && apt-get install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/saswawa/relay/main/s.sh | tr -d '\r')
```

# Socks5 转 VLESS 极简中转面板 (Socks5 to VLESS Relay Panel)

这是一个轻量级的一键脚本，用于在 VPS 上部署一个基于 Sing-box 的中转面板。它可以将上游的 Socks5 代理转换为更安全的 VLESS Reality 协议，或者提供直连的 VLESS 和 Socks5 服务。

## ✨ 主要功能 (v3.4)

*   **极简 Web 面板**：基于 Flask 开发的轻量级 Web 管理界面，支持可视化添加、删除和管理转发规则。
*   **协议转换**：
    *   将上游 Socks5 节点转换为 **VLESS Reality** (防探测) 协议供客户端连接。
    *   同时提供本地 Socks5 端口直接连接。
*   **本机直连节点**：
    *   默认提供本机 VLESS Reality 直连 (端口 10086)。
    *   默认提供本机 Socks5 直连 (端口 10087)。
*   **密钥固化**：重新安装脚本或从备份恢复时，自动保留 Reality 密钥对，无需重新分发订阅链接。
*   **自动化管理**：
    *   自动配置防火墙 (UFW / iptables)。
    *   Systemd 服务守护，开机自启。
    *   支持一键通过链接导入上游 Socks5 节点。
*   **一键自检**：面板内置连接性测试功能。

## 🚀 安装指南

### 系统要求
*   OS: Debian 10+ / Ubuntu 20.04+
*   架构: AMD64 / ARM64
*   权限: Root 用户

### 一键安装命令
在终端中执行以下命令即可完成安装（如果之前运行过，会自动检测并保留配置）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/saswawa/relay/main/s.sh | tr -d '\r')
```

> 注意：如果是本地文件安装，请直接运行 `bash s.sh`。

## 📖 使用说明

### 1. 初始化
安装完成后，访问 `http://你的服务器IP:5000`。
首次访问需要设置管理员 **用户名** 和 **密码**。（admin:admin）

### 2. 面板功能
*   **本机直连节点**：
    *   可以直接复制 VLESS 或 Socks5 链接到客户端使用。
    *   VLESS 端口：`10086`
    *   Socks5 端口：`10087`
*   **添加转发**：
    *   输入备注名。
    *   输入上游 Socks5 链接 (支持 `socks5://user:pass@ip:port` 或 Base64 编码连接)。
    *   点击“新增转发”，系统会自动分配入站端口。
*   **管理**：
    *   查看所有转发规则的入站链接 (VLESS / Socks5)。
    *   **自检**：点击“自检”按钮测试上游节点的连通性。
    *   **删**：删除不再需要的转发规则，端口会自动释放。
*   **修改密码**：点击右上角“改密”按钮修改面板登录密码。

### 3. 注意事项
*   脚本会根据当前系统 IP 生成订阅链接，如果是在 NAT VPS 后，请手动替换为公网 IP。
*   默认 Web 面板端口为 `5000`，请确保云服务商安全组已放行该端口。
*   本脚本仅供学习交流使用。

## 📂 文件结构
*   `/root/sbox-relay/` : 程序工作目录
    *   `app.py` : 面板后端源码
    *   `data.json` : 转发规则数据
    *   `admin.json` : 管理员账户信息
    *   `keys.conf` : Reality 密钥备份
    *   `templates/` : 前端 HTML 模板
*   `/etc/sing-box/config.json` : Sing-box 核心配置文件

## 🛠️ 常用命令

*   查看服务状态：
    ```bash
    systemctl status sbox-web sing-box
    ```
*   查看服务日志：
    ```bash
    journalctl -u sbox-web -f
    ```
    ```bash
    journalctl -u sing-box -f
    ```
*   重启服务：
    ```bash
    systemctl restart sbox-web sing-box
    ```
