# AgentSSH 客户端

在你有管理权限的 Linux 容器或服务器中运行，让设备主动连接控制台。无需公网 IP，也无需向容器开放入站端口；运行环境需要能够通过 HTTPS/WSS 访问控制台。

本仓库仅包含客户端源码、客户端构建工具和 Linux 静态可执行文件。控制台、网关、前端、数据库及管理员凭据单独维护，不包含在本仓库。

## 下载并启动

### Linux amd64 / x86_64

```bash
curl -fL https://raw.githubusercontent.com/sandrauzbmo/ssh_tool/main/agentssh -o agentssh
chmod +x agentssh
./agentssh --server https://console.example/agentssh/
```

### Linux arm64 / aarch64

```bash
curl -fL https://raw.githubusercontent.com/sandrauzbmo/ssh_tool/main/bin/agentssh-linux-arm64 -o agentssh
chmod +x agentssh
./agentssh --server https://console.example/agentssh/
```

也可以直接克隆。在 Linux amd64 上，仓库根目录的 `agentssh` 就是通用可执行文件：

```bash
git clone https://github.com/sandrauzbmo/ssh_tool.git
cd ssh_tool
sha256sum -c SHA256SUMS
./agentssh --server https://console.example/agentssh/
```

ARM64 克隆用户执行 `./bin/agentssh-linux-arm64 --server https://console.example/agentssh/`。使用 `uname -m` 确认架构。上面的命令从本仓库下载 `v0.2.1` 客户端编译文件。SHA-256 见 [SHA256SUMS](SHA256SUMS) 和 [deployment/RELEASE.json](deployment/RELEASE.json)。克隆仓库后可一次校验两个架构文件。

**把示例地址替换为你自己的控制台 HTTPS 地址，并保留实际部署路径。** 每次运行都必须传入 `--server`；程序不会使用内置地址，也不携带某个部署的注册信息。客户端会从选定控制台获取授权设置、生成本机身份并自动注册。控制台需要提供兼容的自动注册入口；未开放时，请联系该控制台管理员。无需在目标机器安装 Go、Node、Python 或额外动态库。

默认前台运行，Ctrl+C 正常退出。保持终端进程运行时，设备才会保持连接；断网后自动退避重连。进入控制台的设备列表查看设备，在线状态和本机 SSH 是否可达分别显示。v0.2.0 使用 15～20 秒心跳和双向 WebSocket 保活；每次成功连接后重置退避，连续失败的重试间隔最多 15 秒。更新时保留原状态目录即可沿用设备身份。

## 云端账户注册标记

云端任务可为每个沙箱指定首次注册名称及对应的控制台账户 ID：

```bash
./agentssh --server https://console.example/agentssh/ --name wb-account-sandbox --cookie-account-id YOUR_CONSOLE_ACCOUNT_ID
```

`--cookie-account-id` 是非敏感的账户引用，不是 Cookie 值；名称及 ID 随原有注册请求发送，不额外建立连接。它们保存在本机状态中，重启保持。只有首次注册会采用 `--name` 作为设备名称，已有设备名称由控制台管理。

名称标记用于定位账户。控制台会核验该沙箱的一次性签名绑定后，通过同一次 SSH 任务会话写入受限凭据文件并执行脚本；仅提供名称或账户 ID 不会获得 Cookie。缺少有效绑定时停止，不逐个账户试探。此流程需要兼容的私有控制台；已有设备重连不会补发自动任务。

## 从控制台进入容器 SSH

设备注册成功并不等于获得操作系统 SSH 登录权限。此公开客户端不会创建账户、安装 sshd、开启 root 登录或修改 `authorized_keys`。

1. 确认目标容器已有原生 SSH 服务，默认监听 `127.0.0.1:22`，并允许使用所选账户登录。
2. 在控制台创建“用户名 + 密码”或“用户名 + 私钥”凭据，关联设备或设备分组；也可以首次打开终端时临时输入，仅本次使用。
3. SSH 主机指纹处理遵循所连接控制台的策略，操作与变更记录由控制台管理。
4. 点击设备“终端”，即可操作目标容器的原生 SSH。

如果容器已有 SSH 服务使用其他回环端口，在**本机**显式指定：

```bash
./agentssh --server https://console.example/agentssh/ --ssh-target 127.0.0.1:2222
```

只允许回环 IP，不允许面板指定任意远端地址。没有本机 SSH 服务时，设备仍可注册并在线，但终端会提示 SSH 不可达。

自动注册不会授权远程控制台修改本机 SSH 公钥。公钥初始化需要本机明确授权的设置及相应账户权限。

## 状态、诊断与身份

```bash
./agentssh version
./agentssh status
./agentssh doctor --server https://console.example/agentssh/
```

非 root 默认状态目录为 `$XDG_STATE_HOME/agentssh`；未设置时使用 `~/.local/state/agentssh`。目录权限 0700，身份文件 0600。保留该目录，重启和更新程序就会使用同一设备身份。不要把状态目录复制给其他机器，也不要提交到 Git。

容器重建时需要把状态目录放在持久卷中。若进程以另一用户运行，或状态目录丢失，可能创建新的设备身份。

## 多个控制台与升级

同一状态目录绑定一个控制台，防止把已有设备身份或本机配置误用于其他控制台。为不同控制台分别指定状态目录：

```bash
./agentssh --server https://console-a.example/agentssh/ --state-dir "$HOME/.local/state/agentssh-a"
./agentssh --server https://console-b.example/agentssh/ --state-dir "$HOME/.local/state/agentssh-b"
```

从旧版升级时，先停止旧进程，保留原来的身份、配置和状态记录，再替换可执行文件并传入原控制台地址。已有设备会沿用原身份，不重复注册。若旧身份缺少所属控制台记录，程序会明确报错并保留文件；恢复原记录或为另一控制台使用独立目录。

私有 CA 可通过本机文件显式指定，证书和主机名检查仍然启用：

```bash
./agentssh --server https://console.example/agentssh/ --ca-file /path/to/trusted-ca.pem
```

若管理员要求导入本机配置，通过标准输入传入，避免把敏感设置放在命令行：

```bash
./agentssh configure --server https://console.example/agentssh/ < /path/to/private-config.json
./agentssh --server https://console.example/agentssh/
```

## 显式安装 systemd 服务

先前台运行完成注册，再 Ctrl+C 退出。支持 systemd 且具有相应安装权限的机器可执行：

```bash
sudo ./agentssh install --server https://console.example/agentssh/ --state-dir "$HOME/.local/state/agentssh"
systemctl status agentssh
journalctl -u agentssh -f
sudo ./agentssh uninstall
```

如果使用自定义 XDG 状态目录，请把 `--state-dir` 改为实际目录；自定义 SSH 端口需同时传入 `--ssh-target`。安装会迁移已注册身份到 `/var/lib/agentssh`，以独立低权限账户运行。默认卸载只卸载本项目服务并保留身份，不关闭 sshd、不删除系统账户或原有 SSH 公钥。容器没有 systemd 时使用前台模式，交给容器自身的进程管理方式运行。

本次发布未在运行 systemd 的目标环境完成实际安装/卸载验收；身份迁移逻辑已自动化测试。

## 从源码构建

需要 Go 1.27.0 或更高版本，发行构建使用 Go 1.27.3。只构建客户端，不需要 Node、前端或数据库。

```bash
bash scripts/build.sh
```

输出为 `dist/agentssh-linux-amd64`、`dist/agentssh-linux-arm64` 和校验文件。默认生成通用客户端，无需已有编译文件、部署公钥或签名工具。构建结果不附加部署配置；运行时传入 `--server`。构建可通过 `AGENTSSH_GO` 指定 Go 可执行文件。

```bash
make test
make race
make vet
```

构建依赖及许可证见 [NOTICE.md](NOTICE.md) 和 [third_party](third_party/)。安全边界与手工更新见 [SECURITY.md](SECURITY.md)。
