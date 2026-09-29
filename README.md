# 🚀 网络工具集合

**一键部署多种网络工具的综合解决方案**

---

## 📑 目录

- [🛡️ Hysteria2 一键部署工具](#-hysteria2-一键部署工具)
  - [✨ 核心特性](#-核心特性)
  - [🚀 快速开始](#-快速开始)
  - [🔧 技术架构](#-技术架构)
  - [🔥 防火墙配置](#-防火墙配置)
  - [📊 功能详解](#-功能详解)
  - [📥 配置文件下载](#-配置文件下载)
  - [💻 客户端支持](#-客户端支持)
  - [⚠️ 重要说明](#️-重要说明)

- [📦 ArgoSB Python版本](#-argosb-python版本)
  - [📋 使用方法](#-使用方法)
  - [🔧 配置选项](#-配置选项)
  - [📁 文件结构](#-文件结构)
  - [✅ 优势特点](#-优势特点)

- [Streamlit Upterm 自动启动](#streamlit-upterm-自动启动)

- [🌐 Glitch 网站保活脚本](#-glitch-网站保活脚本)
  - [🔥 主要功能](#-主要功能)
  - [💾 安装与使用](#-安装与使用)
  - [⚙️ 参数说明](#️-参数说明)
  - [🔄 工作原理](#-工作原理)
  - [🖥️ 后台运行](#️-后台运行)

- [🐧 Ubuntu Proot 环境](#-ubuntu-proot-环境)
  - [⚡ 一键安装](#-一键安装)
  - [🎯 功能特点](#-功能特点)
  - [🔄 环境管理](#-环境管理)
  - [📦 预装软件](#-预装软件)

- [👨‍💻 作者信息](#-作者信息)
- [📄 许可证](#-许可证)

---

## 🛡️ Hysteria2 一键部署工具

> **防墙增强版 - 专业的Hysteria2部署脚本，支持多端口配置、Salamander混淆、nginx Web伪装和BBR优化**

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🎯 **一键部署** | 单命令完成所有配置 |
| 🔄 **多端口配置** | 支持生成100个不同端口的节点配置 |
| 🔒 **Salamander混淆** | 自动生成混淆密码，防DPI检测 |
| 🌐 **nginx Web伪装** | TCP端口显示正常企业网站 |
| ⚡ **BBR优化** | 启用BBR拥塞控制算法，提升网络性能 |
| 🔒 **自动HTTPS证书** | 支持Let's Encrypt自动申请和续期 |
| 🔧 **完整清理** | 删除时自动清理所有配置 |
| 📥 **配置下载** | 自动生成并提供多平台配置文件下载 |

### 🚀 快速开始


#### 📥 一键部署
```bash
# 方式一：wget下载
cd ~ && wget https://raw.githubusercontent.com/zhumengkang/agsb/main/nginx-hysteria2.py && python3 nginx-hysteria2.py install --simple --port-range 28888-29999 --enable-bbr


# 方式二：curl下载  
cd ~ && curl -O https://raw.githubusercontent.com/zhumengkang/agsb/main/nginx-hysteria2.py && python3 nginx-hysteria2.py install --simple --port-range 28888-29999 --enable-bbr

```

#### 📥 下载脚本

```bash
# 方式一：wget下载
wget https://raw.githubusercontent.com/zhumengkang/agsb/main/nginx-hysteria2.py

# 方式二：curl下载  
curl -O https://raw.githubusercontent.com/zhumengkang/agsb/main/nginx-hysteria2.py
```

#### ⚡ 最简部署

```bash
# 一键部署 (推荐)
python3 nginx-hysteria2.py install --simple
```

#### 🏆 高性能部署

```bash
# 高位端口 + BBR优化 + 完整防护
python3 nginx-hysteria2.py install --simple --port-range 28888-29999 --enable-bbr
```

#### 🌟 完整配置示例

```bash
# 最强配置：真实域名 + 端口跳跃 + BBR优化
python3 nginx-hysteria2.py install --simple \
  --domain yourdomain.com \
  --use-real-cert \
  --email your@email.com \
  --port-range 28888-29999 \
  --enable-bbr
```

### 📋 基础命令

| 命令 | 功能 |
|------|------|
| `python3 nginx-hysteria2.py help` | 查看帮助 |
| `python3 nginx-hysteria2.py install --simple` | 简化一键部署 |
| `python3 nginx-hysteria2.py status` | 查看状态 |
| `python3 nginx-hysteria2.py client` | 显示客户端配置 |
| `python3 nginx-hysteria2.py del` | 完全删除 |
| `python3 nginx-hysteria2.py fix` | 修复配置 |
| `kk` | **全局管理菜单** (部署后可用) |

### 🎛️ 全局管理菜单 (kk命令)

部署完成后，您可以在任何位置使用 `kk` 命令进入交互式管理菜单：

| 选项 | 功能 | 说明 |
|------|------|------|
| **1** | 查看节点信息 | 显示443端口地址和10个随机v2ray地址 |
| **2** | 查看配置文件 | 显示下载链接和本地配置文件状态 |
| **3** | 查看服务状态 | 检查Hysteria2、nginx和端口监听状态 |
| **4** | 重启服务 | 重启Hysteria2服务 |
| **5** | 查看日志 | 显示最新50行日志信息 |
| **6** | 删除服务 | 完全删除Hysteria2服务和配置 |
| **0** | 退出 | 退出管理菜单 |

```bash
# 使用方法
kk  # 进入管理菜单
```

### 🔧 技术架构

#### 🌟 Hysteria2 核心特性

**基于UDP/QUIC协议**
- ✅ Hysteria2本质是基于UDP协议的代理工具
- ✅ 使用QUIC协议实现快速、可靠的数据传输
- ❌ **不支持TCP转发**，所有流量都通过UDP承载

**支持的功能**
- ✅ **多端口配置**: 生成100个不同端口的节点配置
- ✅ **Salamander混淆**: 防DPI深度包检测
- ✅ **HTTP/3伪装**: 流量伪装成正常HTTP/3访问
- ❌ **FakeTCP**: Hysteria2不支持此功能

#### 🔄 多端口配置原理

```
客户端连接不同端口 (如: 28888, 28889, 28890...)
         ↓
    iptables DNAT转发
         ↓
  Hysteria2监听端口 (如: 443 UDP)
```

#### 🛡️ 双端口伪装策略

```
TCP 443端口 → nginx → 显示正常企业网站
UDP 443端口 → Hysteria2 → 代理服务
```

#### 🔒 防护层次

1. **多端口配置**: 客户端可选择不同端口，防单一端口封锁
2. **Salamander混淆**: 加密流量特征，防DPI检测
3. **HTTP/3伪装**: 流量看起来像正常HTTP/3网站访问
4. **nginx Web伪装**: TCP端口显示正常企业网站
5. **BBR优化**: 提升UDP传输性能和稳定性

### 🔥 防火墙配置

#### 🎯 默认配置 (--simple)

```bash
# UDP端口范围 (Hysteria2多端口)
sudo ufw allow 1024:1074/udp

# TCP端口 (nginx Web伪装)
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
```

#### ⚙️ 自定义端口范围

```bash
# 如果使用 --port-range 28888-29999
sudo ufw allow 28888:29999/udp  # UDP端口范围
sudo ufw allow 443/tcp          # nginx Web伪装
sudo ufw allow 80/tcp           # HTTP重定向
```

#### 📥 配置下载服务端口

```bash
# 配置文件下载服务（可选）
sudo ufw allow 8080/tcp
```

#### ☁️ 云服务器安全组

如果使用云服务器，还需要在安全组中开放：

- **UDP端口范围**: 1024-1074 (或自定义范围)
- **TCP 443**: HTTPS/nginx
- **TCP 80**: HTTP重定向
- **TCP 8080**: 配置下载服务（可选）

### 📊 功能详解

#### 🔄 多端口配置 (Multi-Port Setup)

**原理**: 使用iptables DNAT规则将端口范围内的流量转发到Hysteria2监听端口

**优势**:
- ✅ 防止单一端口被封锁
- ✅ 增加检测和封锁难度
- ✅ 提高连接稳定性
- ✅ 客户端可选择不同端口

**配置**: `--port-range 起始端口-结束端口`

#### 🔒 Salamander混淆

**原理**: Hysteria2内置的流量混淆算法，加密流量特征

**优势**:
- ✅ 防止DPI深度包检测
- ✅ 隐藏Hysteria2协议特征
- ✅ 降低被识别和封锁的概率

**配置**: 自动生成16位随机密码

#### 🌐 HTTP/3伪装

**原理**: 将Hysteria2流量伪装成正常的HTTP/3网站访问

**优势**:
- ✅ 流量看起来像正常网站访问
- ✅ 降低被监控系统识别的概率
- ✅ 提高隐蔽性

#### 🖥️ nginx Web伪装

**原理**: 在TCP端口部署nginx，显示正常企业网站

**优势**:
- ✅ TCP端口访问显示正常网站
- ✅ 增加迷惑性
- ✅ 双重伪装策略

#### ⚡ BBR优化

**原理**: 启用BBR拥塞控制算法，优化UDP传输性能

**优势**:
- ✅ 提升网络传输速度
- ✅ 降低延迟
- ✅ 优化UDP连接稳定性

### 📁 部署后文件结构

```
~/.hysteria2/
├── cert/                      # SSL证书目录
│   ├── cert.pem              # 证书文件
│   └── key.pem               # 私钥文件
├── config/                   # 配置文件目录
│   └── config.json           # Hysteria2主配置
├── logs/                     # 日志目录
│   └── hysteria.log          # 运行日志
├── web/                      # Web伪装文件
│   ├── index.html            # 伪装网站首页
│   ├── robots.txt            # 搜索引擎文件
│   └── sitemap.xml           # 站点地图
├── configs/                  # 客户端配置目录
│   ├── v2rayn-subscription.txt    # v2rayN多端口订阅
│   ├── multi-port-links.txt       # 多端口配置明文
│   ├── clash.yaml                 # Clash多端口配置
│   └── hysteria2.json             # 官方客户端配置
├── start.sh                  # 启动脚本
├── stop.sh                   # 停止脚本
└── hysteria                  # Hysteria2二进制文件
```

### 📥 配置文件下载

部署完成后，脚本会自动启动HTTP服务器提供配置文件下载：

| 配置类型 | 下载地址 | 说明 |
|----------|----------|------|
| **v2rayN多端口订阅** | `http://你的服务器IP:8080/v2rayn-subscription.txt` | Base64编码订阅文件，包含100个节点 |
| **多端口配置明文** | `http://你的服务器IP:8080/multi-port-links.txt` | 明文链接，便于查看和手动导入 |
| **Clash多端口配置** | `http://你的服务器IP:8080/clash.yaml` | Clash Meta配置，包含多个端口节点 |
| **官方客户端配置** | `http://你的服务器IP:8080/hysteria2.json` | Hysteria2官方客户端JSON配置 |

### 💻 客户端支持

| 平台 | 客户端 | 多端口支持 | 推荐度 | 使用方法 |
|------|--------|------------|--------|----------|
| **Windows** | v2rayN | ✅ | ⭐⭐⭐⭐⭐ | 导入多端口订阅或手动添加节点 |
| **Windows** | Hysteria2官方 | ✅ | ⭐⭐⭐⭐⭐ | 使用官方客户端配置 |
| **Android** | v2rayNG | ✅ | ⭐⭐⭐⭐ | 导入订阅或手动添加节点 |
| **Android** | Hysteria2官方 | ✅ | ⭐⭐⭐⭐⭐ | 使用官方客户端配置 |
| **iOS** | Shadowrocket | ✅ | ⭐⭐⭐⭐ | 手动添加节点 |
| **macOS** | ClashX Meta | ✅ | ⭐⭐⭐⭐ | 导入Clash配置 |
| **Linux** | Hysteria2官方 | ✅ | ⭐⭐⭐⭐⭐ | 使用官方客户端配置 |

#### 📱 客户端配置指南

**🔹 v2rayN用户:**
- **多端口订阅**: 下载v2rayN多端口订阅 → 添加订阅链接
- **手动导入**: 下载多端口配置明文 → 复制链接到v2rayN

**🔹 Clash Meta用户:**
- **多端口配置**: 下载Clash多端口配置，包含多个端口节点

**🔹 官方客户端用户:**
- **官方配置**: 使用官方客户端配置文件

### ⚠️ 重要说明

#### 🎯 技术要点

1. **Hysteria2基于UDP协议**: 不是TCP转发，所有流量通过UDP承载
2. **多端口配置**: 提供100个不同端口的节点，用户可手动选择切换
3. **配置兼容性**: 生成的配置兼容多种客户端
4. **防火墙要求**: 必须开放UDP端口，TCP端口用于Web伪装

#### 🔧 故障排除

| 问题 | 解决方案 |
|------|----------|
| **连接失败** | 检查UDP端口是否开放 |
| **多端口不生效** | 确认使用正确的配置文件 |
| **Web伪装无效** | 检查nginx配置和TCP端口 |
| **混淆连接失败** | 确认客户端混淆密码正确 |

---

## 📦 ArgoSB Python版本

> **无需root权限的Python版本，完全适用于普通用户**

### 📋 使用方法

#### ⚡ 一键安装命令

```bash
# 免费vps免root一键安装hysteria2
cd ~ && curl -fsSL https://raw.githubusercontent.com/zhumengkang/agsb/main/hysteria2-v1.py | python3 -

# 免费vps免root一键安装vmess
cd ~ && curl -fsSL https://raw.githubusercontent.com/zhumengkang/agsb/main/agsb-v2.py | python3 - install --uuid b1ebd5fc-9170-45d4-9887-a39c9fc65298 --port 49999 --agk CF-token --domain 自己的域名

# wget方式下载
cd ~ && wget https://raw.githubusercontent.com/zhumengkang/agsb/main/agsb.py && python3 agsb.py install

# curl方式下载
cd ~ && curl -fsSL https://raw.githubusercontent.com/zhumengkang/agsb/main/agsb.py | python3 -
```

#### 🎯 基础操作

| 命令 | 功能 |
|------|------|
| `python3 agsb.py install` | 安装服务 |
| `agsb` / `python3 agsb.py` | 启动服务 |
| `agsb status` | 查看服务状态 |
| `agsb cat` | 查看单行节点列表 |
| `agsb update` | 升级脚本 |
| `agsb uninstall` / `agsb del` | 卸载服务 |

### 🔧 配置选项

#### 🌍 环境变量设置

```bash
export vmpt=10000              # 指定vmess端口
export uuid=your-uuid          # 指定UUID
export agn=your-domain         # 指定Argo固定域名
export agk=your-token          # 指定Argo授权密钥

python3 agsb.py
```

#### 💻 固定域名安装

```bash
cd ~ && curl -fsSL https://raw.githubusercontent.com/zhumengkang/agsb/main/agsb-v2.py | python3 - install --uuid b1ebd5fc-9170-45d4-9887-a39c9fc65298 --port 49999 --agk CF-token --domain 自己的域名
```

### 📁 文件结构

```
~/.agsb/                       # 用户主目录下的隐藏文件夹
├── sing-box                   # sing-box可执行文件
├── cloudflared               # cloudflared可执行文件
├── sb.json                   # sing-box配置文件
├── list.txt                  # 节点信息列表
└── allnodes.txt              # 单行节点列表文件

~/bin/                        # 命令链接目录
└── agsb                      # 命令链接
```

### ✅ 优势特点

| 特性 | 描述 |
|------|------|
| 🔐 **无需root权限** | 普通用户即可使用 |
| 📁 **用户目录安装** | 安装在用户主目录下的隐藏文件夹 |
| 🐍 **现代Python语法** | 使用Python 3编写，语法更现代 |
| 📦 **仅使用标准库** | 无需安装任何额外依赖 |
| 🔄 **保留核心功能** | 保留了原shell脚本的所有功能 |
| 🔗 **便捷命令链接** | 自动创建用户目录下的命令链接 |
| 🛠️ **友好错误处理** | 更友好的错误处理和调试信息 |
| 📋 **节点输出功能** | 提供直接输出节点功能，方便复制使用 |

### 🔧 兼容性提示

- ✅ 需要Python 3环境，无需安装额外依赖
- ✅ 所有文件都安装在用户目录下，不影响系统目录
- ✅ 安装完成后会在`~/bin`目录创建命令链接
- ⚠️ 请确保`~/bin`目录在PATH环境变量中

---

## Streamlit Upterm 自动启动

`upload-yuancheng.py` 是 Streamlit 入口。打开应用页面后，脚本先在后台启动 `agsb-v2.py`，再启动 Upterm；私有应用需先登录。只有 Uvicorn 日志时，先确认页面已加载。Upterm 就绪后，Streamlit Community Cloud 的应用日志会输出 `Upterm SSH connection: ssh ...`，失败时输出 `[upterm]` 诊断和退出码。连接命令不写入 TXT 文件，也不上传到第三方文件服务。

通过环境变量或 Streamlit Secrets 配置：

```bash
export UUID="your-uuid"
export PORT=19999
export AGK="your-cloudflare-tunnel-token"
export DOMAIN="your.domain.example"
```

默认启动的 Upterm 会话允许任何持有日志中 SSH 连接命令的人进入可写 shell。可选用 `UPTERM_AUTHORIZED_USER=github:your-username`、`UPTERM_AUTHORIZED_KEY`（一行 SSH 公钥）或 `UPTERM_AUTHORIZED_KEYS`（每行一个原始 SSH 公钥的文件路径）限制连接者。请限制 Streamlit 应用日志的访问权限。`UUID` 仅用于 sing-box，Upterm 不使用它。

仓库自带 [Upterm 官方 v0.33.0](https://github.com/owenthereal/upterm/releases/tag/v0.33.0) 的 Linux x86_64 和 arm64 可执行文件，位于 `bin/`，许可证见 `bin/UPTERM-LICENSE`。启动时校验 SHA-256 并复制到 `~/upterm`，不再从网络下载；也可用 `UPTERM_BIN` 指向预装的可执行文件。容器通过 `wss://uptermd.upterm.dev` 的 443 端口连接中继，并固定官方中继主机密钥，不需要在容器内运行 `sshd`。日志直接输出 `ssh 用户名@uptermd.upterm.dev`，连接端只需 SSH 客户端且须能访问中继的 TCP 22 端口。Streamlit 重跑时会查询并重用已有会话；授权配置改变时会停止旧会话并建立新会话。

Cloudflare 隧道仍使用 `AGK`。`PORT` 是 sing-box 本地端口（未设置时默认 `49999`），`DOMAIN` 是 Cloudflare 的 Public Hostname；Upterm 公共中继不经过这个域名或 19999 端口。在 Cloudflare Zero Trust 中将现有 `DOMAIN` 路由保持为 `http://localhost:PORT`。隧道 token 仅连接已有隧道，不会自动创建 Public Hostname 路由。Streamlit 启动不修改 crontab。

## 🌐 Glitch 网站保活脚本

> **模拟真人浏览行为，防止 Glitch 项目休眠**

### 🔥 主要功能

| 功能 | 描述 |
|------|------|
| 🤖 **模拟真人浏览** | 防止被识别为机器人 |
| ⏰ **自定义访问间隔** | 支持自定义访问间隔时间 |
| 🧠 **智能会话管理** | 模拟真实用户访问模式 |
| 🌐 **多User-Agent支持** | 支持多种浏览器和设备 |
| 💾 **自动缓存处理** | 自动处理缓存和ETag，减少服务器负担 |
| 📝 **完整日志记录** | 完整的日志记录功能 |
| 🔧 **命令行参数** | 支持通过命令行参数自定义配置 |

### 💾 安装与使用

#### 📦 安装依赖

```bash
pip install requests
```

#### ⚡ 一键安装并运行

```bash
# 使用curl - 默认URL
curl -fsSL https://raw.githubusercontent.com/zhumengkang/agsb/main/cron-glitch.py | python3 -

# 使用curl - 指定URL
curl -fsSL https://raw.githubusercontent.com/zhumengkang/agsb/main/cron-glitch.py | python3 - -u https://your-project-name.glitch.me

# 使用curl - 指定URL和访问间隔
curl -fsSL https://raw.githubusercontent.com/zhumengkang/agsb/main/cron-glitch.py | python3 - --url https://your-project-name.glitch.me --interval 30-180
```

#### 📥 下载方式

```bash
# 使用wget下载
wget https://raw.githubusercontent.com/zhumengkang/agsb/main/cron-glitch.py -O glitch.py

# 使用curl下载
curl -fsSL https://raw.githubusercontent.com/zhumengkang/agsb/main/cron-glitch.py -o glitch.py
```

#### 🎯 基本使用

```bash
# 默认设置运行
python3 glitch.py

# 指定目标URL
python3 glitch.py -u https://your-project-name.glitch.me

# 自定义访问间隔（30-180秒）
python3 glitch.py -i 30-180

# 显示详细日志
python3 glitch.py -v
```

### ⚙️ 参数说明

| 参数 | 长参数 | 描述 | 默认值 |
|------|--------|------|--------|
| `-u URL` | `--url URL` | 要访问的目标 URL | `https://seemly-organized-thing.glitch.me/` |
| `-i INTERVAL` | `--interval INTERVAL` | 请求间隔范围(秒)，格式："最小值-最大值" | `"60-240"` |
| `-v` | `--verbose` | 显示详细日志 | - |
| `-b` | `--background` | 在后台运行 | - |
| `-l` | `--list` | 列出正在运行的实例 | - |
| `-s` | `--stop` | 停止所有运行的实例 | - |
| `-d` | `--delete` | 删除指定 URL 的会话记录 | - |
| `-c` | `--clear-all` | 清除所有会话记录 | - |

### 🔄 工作原理

1. **随机时间间隔**: 在指定的时间间隔内随机选择一个时间点发送请求
2. **浏览器指纹模拟**: 每次请求都会使用不同的浏览器指纹信息
3. **会话状态保持**: 会话管理系统保持 Cookie 和会话状态
4. **ETag缓存支持**: 支持 ETag 缓存机制，减少服务器负担
5. **人类行为模拟**: 模拟人类浏览行为，如滚动、点击等

### 🖥️ 后台运行

#### 🚀 内置后台功能

脚本提供了内置的后台运行功能，**不依赖外部的nohup命令**，在各种环境下都能正常工作。

```bash
# 在后台运行（默认URL）
python3 glitch.py -b

# 在后台运行并指定URL
python3 glitch.py -b -u https://your-project-name.glitch.me

# 在后台运行并指定URL和访问间隔
python3 glitch.py -b -u https://your-project-name.glitch.me -i 30-180
```

#### 🔧 管理后台进程

```bash
# 列出所有正在运行的脚本实例
python3 glitch.py -l

# 停止所有正在运行的脚本实例
python3 glitch.py -s
```

#### 📄 查看日志

```bash
# 查看完整日志
cat glitch.log

# 实时查看日志更新
tail -f glitch.log
```

#### ⚠️ 注意事项

- 脚本会在当前目录创建 `cookies` 文件夹存储会话信息
- 日志会同时输出到控制台和 `requests.log` 文件
- 为避免 Glitch 项目休眠，建议将访问间隔设置在 5 分钟以内
- 使用 Ctrl+C 可以随时中断脚本运行

---

## 🐧 Ubuntu Proot 环境

> **无需root权限的完整Ubuntu环境**

### ⚡ 一键安装

```bash
# wget方式
cd ~ && wget https://raw.githubusercontent.com/zhumengkang/agsb/main/root.sh && chmod +x root.sh && ./root.sh

# curl方式
cd ~ && curl -sSL https://raw.githubusercontent.com/zhumengkang/agsb/main/root.sh -o root.sh && chmod +x root.sh && ./root.sh
```

### 🎯 功能特点

| 特性 | 描述 |
|------|------|
| 🔍 **自动架构检测** | 支持x86_64和aarch64架构 |
| 🐧 **Ubuntu 20.04基础** | 下载并安装Ubuntu 20.04基础系统 |
| 🌐 **自动DNS配置** | 自动配置DNS服务器 |
| 📦 **软件源更新** | 更新软件源为Ubuntu 22.04 (Jammy) |
| 👤 **用户目录创建** | 自动创建与物理机用户同名的用户目录 |
| 🛠️ **开发工具安装** | 安装常用开发工具和软件包 |
| 🎨 **美观界面** | 彩色界面和提示信息 |
| 🔐 **无需root权限** | 普通用户即可使用 |
| 🗑️ **一键删除** | 支持一键删除所有配置和文件 |

### 🔧 基本命令

| 命令 | 功能 |
|------|------|
| `./root.sh` | 安装Ubuntu Proot环境 |
| `./root.sh del` | 删除所有配置和文件 |
| `./root.sh help` | 显示帮助信息 |
| `./start-proot.sh` | 启动Proot环境 |

### 🔄 环境管理

#### 🚀 进入Proot环境

**首次安装**: 安装时会询问是否立即启动proot环境

**再次进入**:
```bash
./start-proot.sh
```

#### 🚪 退出Proot环境

在proot环境中执行：
```bash
exit
```

#### 🔍 环境识别

在proot环境中，命令提示符会显示为`proot-ubuntu:/当前目录$`的形式

#### 🗑️ 删除环境

```bash
./root.sh del
```

### 📦 预装软件

脚本会自动安装以下软件包：

#### 🔧 基础工具
- `curl`, `wget`, `git`
- `vim`, `nano`
- `zip`, `unzip`
- `tree`

#### 🖥️ 系统工具
- `htop`, `tmux`
- `net-tools`
- `iproute2`
- `cron`

#### 💻 开发环境
- `python3`, `python3-pip`
- `nodejs`, `npm`
- `build-essential`

#### 🔒 系统组件
- `sudo`
- `locales`
- `ca-certificates`
- `gnupg`
- `lsb-release`
- `podman`

### 🔧 常见问题解决

#### ❌ Proot环境无法正常启动

**检查项目**:
1. 是否有足够的磁盘空间
2. 是否有网络连接
3. 系统架构是否受支持

**解决方案**:
```bash
./root.sh del
./root.sh
```

#### 🌐 在proot环境中无法访问网络

**DNS配置修复**:
```bash
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
```

---

## 👨‍💻 作者信息

| 平台 | 链接 |
|------|------|
| **作者** | 康康 |
| **GitHub** | https://github.com/zhumengkang/ |
| **YouTube** | https://www.youtube.com/@康康的V2Ray与Clash |
| **Telegram** | https://t.me/+WibQp7Mww1k5MmZl |

---

## 📄 许可证

本项目基于 **MIT License** 开源 - 详见 [LICENSE](LICENSE) 文件

---

## 🙏 支持与贡献

- ⭐ 如果您喜欢这个项目，请在GitHub上给我一个Star
- 📺 欢迎关注我的YouTube频道获取最新教程
- 💬 如有问题或建议，欢迎通过GitHub Issues或Telegram群组联系我
- 🤝 欢迎提交Pull Request贡献代码

---

## 🏆 赞助商

[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")

---

**⚠️ 免责声明**: 此工具仅供学习和技术研究使用，请遵守当地法律法规。
