package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sandrauzbmo/ssh_tool/internal/agent"
	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
)

func main() {
	if e := run(); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "agentssh:", e)
		os.Exit(1)
	}
}
func run() error {
	return runArgs(os.Args[1:])
}
func runArgs(args []string) error {
	command := "run"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		command = args[0]
		args = args[1:]
	}
	flags := flag.NewFlagSet("agentssh", flag.ContinueOnError)
	state := flags.String("state-dir", agent.DefaultState(), "本机私有状态目录")
	server := flags.String("server", "", "必填：控制台HTTPS地址，包含部署路径")
	caFile := flags.String("ca-file", "", "可选：本机可信CA证书文件")
	target := flags.String("ssh-target", "127.0.0.1:22", "本机回环SSH地址")
	confirm := flags.Bool("confirm", false, "确认显式身份重置")
	purge := flags.Bool("purge-identity", false, "卸载时删除本项目身份")
	account := flags.String("account", "", "显式清理公钥的现有账户")
	deviceID := flags.String("device-id", "", "显式清理项目公钥的设备ID，可在keys-list中查看")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("无法识别的参数")
	}
	switch command {
	case "version":
		fmt.Printf("agentssh %s %s\n", protocol.BuildVersion, "protocol=1")
		return nil
	case "configure":
		lock, e := agent.Lock(*state)
		if e != nil {
			return e
		}
		defer lock.Close()
		var c pack.Config
		decoder := json.NewDecoder(io.LimitReader(os.Stdin, 65537))
		decoder.DisallowUnknownFields()
		if e = decoder.Decode(&c); e != nil {
			return errors.New("请通过stdin输入配置JSON，不要把长期令牌放在命令行")
		}
		if c.Protocol == 0 {
			c.Protocol = protocol.Version
		}
		if c, e = withServer(c, *server, *caFile); e != nil {
			return e
		}
		if e = agent.CheckServerBinding(*state, c.Server); e != nil {
			return e
		}
		if e = agent.SaveConfig(*state, c); e != nil {
			return e
		}
		fmt.Println("本机配置已保存；未启动Agent、未重置身份。")
		return nil
	case "reset-identity":
		if !*confirm {
			return errors.New("需要--confirm；此操作仅供已重新获得管理员授权的设备使用")
		}
		lock, e := agent.Lock(*state)
		if e != nil {
			return e
		}
		defer lock.Close()
		path := filepath.Join(*state, "identity.json")
		if _, e = os.Stat(path); e == nil {
			return os.Rename(path, filepath.Join(*state, fmt.Sprintf("identity.backup-%d.json", time.Now().UnixNano())))
		}
		return e
	case "keys-list":
		if *account == "" {
			return errors.New("请用--account指定已有SSH账户")
		}
		keys, e := agent.ListAuthorizedKeys(*account)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(keys)
	case "keys-remove":
		if *account == "" {
			return errors.New("请用--account明确指定已有SSH账户")
		}
		id := *deviceID
		if id == "" {
			if _, e := os.Stat(filepath.Join(*state, "identity.json")); e != nil {
				return errors.New("身份文件不存在，请先keys-list并用--device-id明确指定")
			}
			identity, e := agent.LoadIdentity(*state)
			if e != nil {
				return e
			}
			id = identity.ID
		}
		return agent.UpdateAuthorizedKey(*account, id, "", true)
	case "install":
		if flags.Lookup("state-dir").Value.String() == agent.DefaultState() {
			if original := os.Getenv("SUDO_USER"); original != "" && original != "root" {
				if u, e := user.Lookup(original); e == nil {
					*state = filepath.Join(u.HomeDir, ".local/state/agentssh")
				}
			}
		}
		c, e := configuration(*state, *server, *caFile)
		if e != nil {
			return e
		}
		return agent.Install(*state, *target, c)
	case "uninstall":
		return agent.Uninstall(*purge)
	case "status":
		b, e := os.ReadFile(filepath.Join(*state, "status.json"))
		if e != nil {
			return e
		}
		var status map[string]any
		if e = json.Unmarshal(b, &status); e != nil {
			return e
		}
		f, e := os.OpenFile(filepath.Join(*state, ".lock"), os.O_RDWR, 0600)
		if e == nil {
			defer f.Close()
			if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
				status["state"] = "stopped"
				syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			}
		}
		_, e = os.Stat("/etc/systemd/system/agentssh.service")
		status["service_installed"] = e == nil
		return json.NewEncoder(os.Stdout).Encode(status)
	}
	c, e := configuration(*state, *server, *caFile)
	if e != nil {
		return e
	}
	a, e := agent.New(c, *state, *target)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if command == "doctor" {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", protocol.Endpoint(c.Server, "healthz", false), nil)
		res, e := a.HTTP.Do(req)
		healthy := e == nil && res.StatusCode == 200
		if res != nil {
			res.Body.Close()
		}
		m := a.Metadata()
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"server": c.Server, "tls_and_https_ok": healthy, "ssh_target": a.Target, "ssh_reachable": m.SSHReachable, "state_dir": *state})
		if !healthy || !m.SSHReachable {
			return errors.New("诊断发现异常，请检查HTTPS信任/网络或本机SSH监听")
		}
		return nil
	}
	if command == "initialize-ssh" {
		return a.InitializeSSH(ctx)
	}
	if command != "run" {
		return errors.New("支持run/version/status/doctor/configure/reset-identity/keys-remove/install/uninstall")
	}
	return a.Run(ctx)
}
