# 全协议中转面板 (Universal Relay Panel)

这是一个强大的一键脚本，用于在 VPS 上部署基于 Sing-box 的多协议中转面板。它不仅支持传统的 Socks5 转发，还全面支持 VLESS、Hysteria2 和 VMess 协议的解析与转换。

一键脚本：
```bash
apt-get update -y && apt-get install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/saswawa/relay/main/s.sh | tr -d '\r')
```

## ✨ 主要功能 (v3.5)

*   **多协议支持**：
    *   **Socks5**: 支持标准 `socks5://` 及 Base64 链接。
    *   **VLESS**: 支持 `vless://` 链接，自动解析 Reality/TLS 配置。
    *   **Hysteria2**: 支持 `hy2://` / `hysteria2://` 链接，支持密码验证与 Obfs 混淆。
    *   **VMess**: 支持 `vmess://` (Base64 JSON)，支持 TCP/WebSocket/GRPC 及 TLS。
*   **安全与隐私**：
    *   **随机面板端口**: 安装时随机生成 10000-65000 之间的 Web 管理端口，避免被扫描爆破。
    *   **协议转换**: 将上游任意协议节点转换为安全的 **VLESS Reality** 协议供客户端连接。
*   **本机直连节点**：
    *   内置本机 VLESS Reality 直连 (端口 10086)。
    *   内置本机 Socks5 直连 (端口 10087)。
*   **自动化管理**：
    *   自动配置防火墙 (UFW / iptables)。
    *   Systemd 服务守护，开机自启。
    *   密钥固化：重装不换号。

## 🚀 安装指南

### 一键安装命令
在终端中执行以下命令即可完成安装：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/saswawa/relay/main/s.sh | tr -d '\r')
```

### 系统要求
*   OS: Debian 10+ / Ubuntu 20.04+
*   权限: Root 用户

## 📖 使用说明

### 1. 访问面板
安装完成后，脚本会输出管理面板地址，例如：
`http://你的服务器IP:58888` (端口为随机高位端口)

### 2. 首次登录
*   **首次访问**面板时，您可以自定义设置管理员的 **用户名** 和 **密码**。
*   请务必牢记设置的密码。

### 3. 添加转发规则
在“新增转发”输入框中，粘贴您的上游节点链接。支持以下格式：
*   `socks5://user:pass@ip:port`
*   `vless://uuid@ip:port?security=reality&...`
*   `hy2://password@ip:port?...`
*   `vmess://eyJhZGQiOiI...` (Base64)

点击添加后，系统会自动分配两个端口：
1.  **VLESS 端口**: 提供 VLESS Reality 协议连接 (推荐)。
2.  **Socks5 端口**: 提供普通 Socks5 协议连接。

## 📂 文件结构
*   `/root/sbox-relay/` : 程序工作目录
    *   `.web_port` : 存储生成的随机 Web 端口
    *   `app.py` : 面板后端源码
    *   `data.json` : 转发规则数据
    *   `config.json` : Sing-box 配置文件

## 🛠️ 常用命令

*   **查看当前 Web 端口**：
    ```bash
    cat /root/sbox-relay/.web_port
    ```
*   **查看服务状态**：
    ```bash
    systemctl status sbox-web sing-box
    ```
