package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
	"github.com/sandrauzbmo/ssh_tool/internal/secure"
)

const serviceUnit = `# Managed by AgentSSH explicit install
[Unit]
Description=AgentSSH outbound SSH tunnel
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=agentssh
Group=agentssh
StateDirectory=agentssh
StateDirectoryMode=0700
ExecStart=/usr/local/lib/agentssh/agentssh --state-dir /var/lib/agentssh
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/agentssh
UMask=0077
LimitNOFILE=4096
[Install]
WantedBy=multi-user.target
`

func ServiceUnit(server, target string) (string, error) {
	canonical, err := protocol.NormalizeServer(server)
	if err != nil {
		return "", err
	}
	if err = protocol.ValidateTarget(target); err != nil {
		return "", err
	}
	quote := func(s string) string {
		s = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`).Replace(s)
		return `"` + s + `"`
	}
	return strings.Replace(serviceUnit, "--state-dir /var/lib/agentssh", "--state-dir /var/lib/agentssh --server "+quote(canonical)+" --ssh-target "+quote(target), 1), nil
}

func Install(sourceState, target string, c pack.Config) error {
	unit, e := ServiceUnit(c.Server, target)
	if e != nil {
		return e
	}
	if e := protocol.ValidateTarget(target); e != nil {
		return e
	}
	if os.Geteuid() != 0 {
		return errors.New("安装系统服务需要root权限，请显式使用sudo")
	}
	if _, e := os.Stat("/run/systemd/system"); e != nil {
		return errors.New("当前环境没有运行systemd；请继续使用前台模式")
	}
	lock, e := Lock(sourceState)
	if e != nil {
		return e
	}
	defer lock.Close()
	identity, e := LoadIdentity(sourceState)
	if e != nil {
		return e
	}
	if !identity.Registered {
		return errors.New("请先在前台完成注册，再安装服务以保持同一身份")
	}
	if e = BindIdentityServer(sourceState, identity, c.Server); e != nil {
		return e
	}
	if e = SaveConfig(sourceState, c); e != nil {
		return e
	}
	if _, e = user.Lookup("agentssh"); e != nil {
		cmd := exec.Command("useradd", "--system", "--home-dir", "/var/lib/agentssh", "--shell", "/usr/sbin/nologin", "agentssh")
		if out, e := cmd.CombinedOutput(); e != nil {
			return fmt.Errorf("创建低权限服务用户失败: %s", out)
		}
	}
	u, e := user.Lookup("agentssh")
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == 0 || gid == 0 || u.HomeDir != "/var/lib/agentssh" {
		return errors.New("现有agentssh账户不是独立低权限服务账户，拒绝复用")
	}
	if e = MigrateState(sourceState, "/var/lib/agentssh", uid, gid); e != nil {
		return e
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	binary, e := os.ReadFile(executable)
	if e != nil {
		return e
	}
	if e = secure.AtomicFile("/usr/local/lib/agentssh/agentssh", binary, 0755); e != nil {
		return e
	}
	if e = os.Chmod("/usr/local/lib/agentssh", 0755); e != nil {
		return e
	}
	path := "/etc/systemd/system/agentssh.service"
	if old, e := os.ReadFile(path); e == nil && !strings.HasPrefix(string(old), "# Managed by AgentSSH") {
		return errors.New("已有非本项目systemd单元，拒绝覆盖")
	}
	if e = secure.AtomicFile(path, []byte(unit), 0644); e != nil {
		return e
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "agentssh.service"}} {
		if out, e := exec.Command("systemctl", args...).CombinedOutput(); e != nil {
			return fmt.Errorf("systemd操作失败: %s", out)
		}
	}
	fmt.Println("AgentSSH服务已安装；保留原设备身份:", identity.ID)
	return nil
}
func Uninstall(purge bool) error {
	if os.Geteuid() != 0 {
		return errors.New("卸载系统服务需要root权限")
	}
	path := "/etc/systemd/system/agentssh.service"
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if !strings.HasPrefix(string(b), "# Managed by AgentSSH") {
		return errors.New("拒绝删除非本项目服务")
	}
	if out, e := exec.Command("systemctl", "disable", "--now", "agentssh.service").CombinedOutput(); e != nil {
		return fmt.Errorf("无法停止服务: %s", out)
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	if out, e := exec.Command("systemctl", "daemon-reload").CombinedOutput(); e != nil {
		return fmt.Errorf("systemd重载失败: %s", out)
	}
	_ = os.Remove("/usr/local/lib/agentssh/agentssh")
	if purge {
		if e = os.RemoveAll("/var/lib/agentssh"); e != nil {
			return e
		}
	}
	fmt.Println("服务已卸载；未改动sshd、系统账户或原有SSH公钥。默认保留身份。")
	return nil
}
