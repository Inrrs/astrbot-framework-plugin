# OpenResty Proxy Manager 插件 (v2)

## 概述

`OpenResty Proxy Manager` 是一个为 AstrBot 设计的插件，旨在通过聊天机器人安全、便捷地管理远程服务器上的 `OpenResty` 反向代理配置。它适用于需要为多个用户或服务动态创建和管理域名代理的场景。

插件内置了完整的审批流程和IP白名单机制，确保所有代理配置都经过授权且安全可靠。

## 主要功能

- **WebUI配置**：所有核心参数（SSH连接、OpenResty路径、审批员）均通过AstrBot管理后台图形化配置，无需记忆复杂指令。
- **纯Python实现**：使用 `asyncssh` 库进行远程操作，无需在宿主机安装 `sshpass` 等外部依赖。
- **多协议支持**：通过 SSH 管理 OpenResty 的 HTTP, HTTPS (七层) 和 TCP/UDP (四层) 反向代理。
- **HTTPS 支持**：通过预置在服务器上的 SSL 证书，轻松启用 HTTPS 代理。
- **审批流程**：普通用户申请端口代理后，需要由指定的管理员审批，通过后配置才会生效并重载 OpenResty 服务。
- **IP 白名单**：只有在白名单内的内网 IP 地址才能作为代理的目标，增强了安全性。
- **端口冲突检测**：在申请和审批阶段自动检测外网端口是否已被占用。
- **保留端口禁用**：为防止意外覆盖常用服务，默认禁止使用 `80`, `443`, `8080`, `8443` 作为反代外网端口。
- **TCP/UDP 自动关联**：当申请 `tcp` 协议时，会自动创建对应的 `udp` 转发规则。
- **原子化配置更新**：远程更新配置时，先上传临时文件并测试语法，成功后再替换旧配置并重载服务，确保服务不中断。
- **权限分离**：严格区分管理员指令和普通用户指令。

## 安装与配置

1.  **安装插件**: 将插件放置于 `data/plugins` 目录下，重启 AstrBot。
2.  **安装依赖**: AstrBot 会自动根据 `requirements.txt` 文件安装 `asyncssh` 依赖。
3.  **配置插件**:
    - 进入 AstrBot WebUI -> 插件管理 -> OpenResty Proxy Manager。
    - 填写 **SSH 配置**：远程服务器的IP、端口、用户名和密码。
    - 填写 **OpenResty 配置**：主域名、各项配置文件的远程路径、SSL证书目录。
    - 在 **审批员** 列表中，添加有权审批申请的管理员QQ号。
    - 保存配置。
4.  **验证配置**: 配置完成后，请务必在聊天窗口发送一次 `/反代 检查环境` 命令，以确保 AstrBot 能够成功连接到远程主机并执行命令。

## 前置要求

- **远程服务器**:
  - 已安装 OpenResty。
  - SSH 服务已开启。
  - 用于连接的SSH用户需要有执行 `sudo openresty`、`sudo mv`、`sudo rm`、`sudo mkdir` 的权限（通常建议配置免密 `sudo`）。
- **AstrBot 服务器**:
  - 可以访问远程服务器的 SSH 端口。

## 附录：服务器环境准备

本附录为初次配置远程服务器的用户提供指导。

### 1. 安装 OpenResty

请根据您的 Linux 发行版选择合适的安装方式。

#### 在 Debian / Ubuntu 上安装

> **注意**: OpenResty 官方源可能尚未支持最新的 Debian/Ubuntu 发行版 (例如 Debian `trixie`)。如果 `apt-get update` 时遇到 `404 Not Found` 或 `does not have a Release file` 错误，这通常意味着您当前的系统代号不受支持。
>
> 此时，您可以手动将仓库配置中的系统代号（如 `trixie`）替换为上一个受支持的稳定版代号（如 `bookworm` for Debian, `jammy` for Ubuntu）。

以下是推荐的安装步骤：

```bash
# 1. 安装依赖
sudo apt-get update
sudo apt-get -y install --no-install-recommends wget gnupg ca-certificates

# 2. 导入 GPG 密钥 (适用于 Debian >= 12 和 Ubuntu >= 22)
wget -O - https://openresty.org/package/pubkey.gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/openresty.gpg

# 3. 添加 OpenResty 官方软件源
# 注意：下面的命令会尝试使用您当前的系统代号。如果失败，请参考上面的提示手动修改。
# 对于 Debian:
# echo "deb http://openresty.org/package/debian $(lsb_release -sc) openresty" | sudo tee /etc/apt/sources.list.d/openresty.list
# 对于 Ubuntu:
# echo "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/openresty.list

# 修复 Trixie 等新版本问题的示例 (使用 bookworm 作为备用):
echo "deb http://openresty.org/package/debian bookworm openresty" | sudo tee /etc/apt/sources.list.d/openresty.list

# 4. 安装 OpenResty
sudo apt-get update
sudo apt-get -y install openresty
```

#### 在 CentOS / RHEL 上安装

```bash
# 1. 添加 yum 源
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://openresty.org/package/centos/openresty.repo

# 2. 安装 OpenResty
sudo yum install -y openresty
```

安装完成后，建议启动并设置开机自启：
```bash
sudo systemctl start openresty
sudo systemctl enable openresty
```

### 2. 放置 SSL 证书 (HTTPS 需求)

如果您需要使用 `https` 协议，请将您的 SSL 证书和私钥文件上传到服务器。

1.  **获取证书**: 您需要一个证书文件 (通常是 `.pem` 或 `.crt` 后缀) 和一个私钥文件 (`.key` 后缀)。
2.  **上传文件**: 将这两个文件上传到您在插件 WebUI **OpenResty 配置** -> **SSL证书路径** 中所指定的目录。
3.  **命名规则**: 插件会根据您在 WebUI 中设置的 **主域名** 来寻找证书文件。例如：
    - 如果您的主域名是 `proxy.example.com`。
    - 插件将会寻找名为 `proxy.example.com.pem` 和 `proxy.example.com.key` 的文件。
    - 请确保您的证书和私钥文件名与主域名完全对应。

### 3. 配置免密 Sudo (重要)

为了安全和自动化，插件要求 SSH 连接的用户能够无密码执行特定的 `sudo` 命令。

1.  **编辑 sudoers 文件**: 在远程服务器上执行 `sudo visudo` 命令。
2.  **添加配置**: 在文件末尾添加以下行，请将 `your_username` 替换为您在插件中配置的 SSH 用户名。

    ```
    # 允许 openresty_proxy_manager 插件执行必要命令
    your_username ALL=(ALL) NOPASSWD: /usr/local/openresty/bin/openresty, /bin/mv, /bin/rm, /bin/mkdir
    ```
    > **注意**: `openresty` 的路径可能因安装方式而异。您可以使用 `which openresty` 或 `sudo which openresty` 命令找到它的确切路径。默认路径通常是 `/usr/local/openresty/bin/openresty`。

3.  **保存退出**: 保存并退出编辑器。

完成以上步骤后，您的服务器环境便已准备就绪。

## 命令文档

所有命令都以 `/反代` 作为前缀。

---

### 管理员指令

> **注意**：以下所有命令都需要管理员权限才能执行。

#### 1. 环境与配置

- **命令**：`/反代 检查环境`
- **说明**：测试与远程服务器的SSH连接，并检查 `openresty` 命令是否可用。
- **示例**：`/反代 检查环境`

- **命令**：`/反代 查看配置`
- **说明**：显示当前在 WebUI 中配置的核心参数。
- **示例**：`/反代 查看配置`

#### 2. 管理审批员 (可选)

除了在 WebUI 中配置，您也可以通过指令动态管理审批员。

- **命令**：`/反代 添加审批员 <QQ号>`
- **说明**：添加一个指定的QQ号为审批员。
- **示例**：`/反代 添加审批员 123456789`

- **命令**：`/反代 删除审批员 <QQ号>`
- **说明**：从审批员列表中移除一个指定的QQ号。
- **示例**：`/反代 删除审批员 123456789`

- **命令**：`/反代 查看审批员`
- **说明**：查看当前的审批员列表。
- **示例**：`/反代 查看审批员`

#### 3. 管理IP白名单

- **命令**：`/反代 白名单添加 <ip1> [ip2]...`
- **说明**：向IP白名单中添加一个或多个IP地址，使用空格分隔。
- **示例**：`/反代 白名单添加 192.168.1.100 192.168.1.101`

- **命令**：`/反代 白名单删除 <ip1> [ip2]...`
- **说明**：从IP白名单中删除一个或多个IP地址，使用空格分隔。
- **示例**：`/反代 白名单删除 192.168.1.101`

- **命令**：`/反代 查看白名单`
- **说明**：查看当前IP白名单列表。
- **示例**：`/反代 查看白名单`

#### 4. 审批与规则管理

- **命令**：`/反代 审批`
- **说明**：查看所有待审批的代理申请。
- **示例**：`/反代 审批`

- **命令**：`/反代 同意 <申请ID1> [申请ID2]...` 或 `/反代 同意 all`
- **说明**：同意一个或多个代理申请。使用 `all` 同意所有待审申请。
- **示例**：
  - `/反代 同意 user123_tcp_25565`
  - `/反代 同意 id_1 id_2 id_3`
  - `/反代 同意 all`

- **命令**：`/反代 拒绝 <申请ID1> [申请ID2]...` 或 `/反代 拒绝 all`
- **说明**：拒绝一个或多个代理申请。使用 `all` 拒绝所有待审申请。
- **示例**：
  - `/反代 拒绝 user123_tcp_25565`
  - `/反代 拒绝 id_1 id_2`
  - `/反代 拒绝 all`

- **命令**：`/反代 查看规则`
- **说明**：查看当前所有已生效的代理规则。
- **示例**：`/反代 查看规则`

#### 5. 直接管理规则

- **命令**：`/反代 添加 <http|https|tcp> <内网IP:端口> <外网端口>`
- **说明**：管理员直接添加一条代理规则，无需审批。如果协议是 `https`，将自动使用配置的“主域名”作为证书名进行匹配。
- **示例**：
  - `/反代 添加 http 192.168.1.100:8080 80`
  - `/反代 添加 https 192.168.1.101:8443 443`
  - `/反代 添加 tcp 192.168.1.102:25565 25565`

- **命令**：`/反代 删除 <外网端口1 或 规则ID1> [外网端口2 或 规则ID2]...`
- **说明**：根据外网端口或规则ID删除一个或多个已生效的规则。
- **示例**：
  - `/反代 删除 80`
  - `/反代 删除 8080 user123_tcp_25565`

---

### 用户指令

#### 1. 申请端口代理

- **命令**：`/反代 申请 <http|https|tcp> <内网IP:端口> <外网端口> <备注>`
- **说明**：提交一个端口反向代理申请。
  - 如果申请 `https`，将自动使用管理员配置的“主域名”作为证书名。
  - 如果申请 `tcp`，将同时为您开启 `udp` 转发。
- **示例**：
  - `/反代 申请 http 192.168.1.101:3000 8081 我的Web服务`
  - `/反代 申请 https 192.168.1.102:8000 443 我的安全服务`
  - `/反代 申请 tcp 192.168.1.103:22 2222 SSH访问`

## 工作流程

1.  **管理员**在 AstrBot WebUI 中完成插件的 **SSH** 和 **OpenResty** 相关配置，并添加**审批员**。
2.  **管理员**使用 `/反代 检查环境` 确认与远程服务器的通信正常。
3.  **管理员**使用 `/反代 白名单 添加` 将允许申请的内网 IP 加入白名单。
4.  **用户**使用 `/反代 申请` 命令提交端口代理请求。
5.  **审批员**收到通知，并使用 `/反代 同意` 或 `/反代 拒绝` 进行处理。
6.  申请通过后，插件会自动更新远程 `OpenResty` 配置并平滑重载服务。
7.  **管理员**可随时使用 `/反代 查看规则` 来审计当前生效的规则。
