package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
	"github.com/sandrauzbmo/ssh_tool/internal/secure"
)

type APIError struct {
	Status        int
	Code, Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s (HTTP %d): %s", e.Code, e.Status, e.Message)
}

type Agent struct {
	MetadataProvider func() protocol.Metadata

	Config           pack.Config
	StateDir, Target string
	Identity         *Identity
	HTTP             *http.Client
	mu               sync.Mutex
	writeMu          sync.Mutex
	dataSlots        chan struct{}
	bootstrapFetched bool
}

func ValidateConfig(c pack.Config) error {
	if len(c.RegistrationName) > 128 || strings.ContainsAny(c.RegistrationName, "\r\n\x00") || len(c.CookieAccountID) > 64 {
		return errors.New("注册名称或账户标记无效")
	}
	for _, r := range c.CookieAccountID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return errors.New("账户标记必须是控制台账户ID")
		}
	}
	_, e := protocol.NormalizeServer(c.Server)
	if e != nil || c.Protocol != protocol.Version {
		return errors.New("需要有效HTTPS地址和支持的协议")
	}
	return nil
}
func New(c pack.Config, state, target string) (*Agent, error) {
	if e := ValidateConfig(c); e != nil {
		return nil, e
	}
	c.Server, _ = protocol.NormalizeServer(c.Server)
	if target == "" {
		target = "127.0.0.1:22"
	}
	if e := protocol.ValidateTarget(target); e != nil {
		return nil, e
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if c.CA != "" && !roots.AppendCertsFromPEM([]byte(c.CA)) {
		return nil, errors.New("部署CA证书无效")
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxIdleConns: 4, IdleConnTimeout: 90 * time.Second}
	return &Agent{Config: c, StateDir: state, Target: target, HTTP: &http.Client{Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}, dataSlots: make(chan struct{}, 4)}, nil
}
func (a *Agent) post(ctx context.Context, path string, body, out any) error {
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, e := http.NewRequestWithContext(ctx, "POST", protocol.Endpoint(a.Config.Server, path, false), bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	res, e := a.HTTP.Do(r)
	if e != nil {
		return errors.New("HTTPS连接失败，请运行doctor检查网络和证书")
	}
	defer res.Body.Close()
	data, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil || len(data) > 65536 {
		return errors.New("服务器响应过大或读取失败")
	}
	if res.StatusCode >= 300 {
		var p struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &p)
		return &APIError{res.StatusCode, p.Code, p.Message}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
func (a *Agent) proof(ctx context.Context, purpose string) (protocol.Proof, error) {
	req := map[string]string{"purpose": purpose, "device_id": a.Identity.ID}
	if purpose == "register" {
		req["public_key"] = a.Identity.Public()
	}
	var response struct {
		Nonce string `json:"nonce"`
	}
	if e := a.post(ctx, "agent/challenge", req, &response); e != nil {
		return protocol.Proof{}, e
	}
	return protocol.Proof{DeviceID: a.Identity.ID, Nonce: response.Nonce, Signature: protocol.Sign(a.Identity.Key(), purpose, a.Identity.ID, response.Nonce)}, nil
}
func (a *Agent) register(ctx context.Context) error {
	p, e := a.proof(ctx, "register")
	if e != nil {
		return e
	}
	var response protocol.RegisterResponse
	if e = a.post(ctx, "agent/register", protocol.RegisterRequest{Proof: p, PublicKey: a.Identity.Public(), BatchID: a.Config.BatchID, Token: a.Config.Token, Metadata: a.Metadata()}, &response); e != nil {
		return e
	}
	if response.DeviceID != a.Identity.ID {
		return errors.New("服务器返回不同身份，拒绝覆盖本地身份")
	}
	a.Identity.Registered = true
	if response.InitUser != "" && !a.Identity.InitApplied {
		if a.Config.AutoUser == "" || response.InitUser != a.Config.AutoUser {
			return errors.New("SSH公钥初始化不符合本机明确授权策略")
		}
		if e = UpdateAuthorizedKey(response.InitUser, a.Identity.ID, response.InitKey, false); e != nil {
			fmt.Fprintln(os.Stderr, "注册成功，但显式SSH公钥初始化失败:", e)
		} else {
			a.Identity.InitApplied = true
			a.Identity.InitUser = response.InitUser
		}
	}
	return SaveIdentity(a.StateDir, a.Identity)
}
func (a *Agent) Run(ctx context.Context) error {
	lock, e := Lock(a.StateDir)
	if e != nil {
		return e
	}
	defer lock.Close()
	a.Identity, e = LoadIdentity(a.StateDir)
	if e != nil {
		return e
	}
	if a.Identity.Revoked {
		return errors.New("设备已撤销，停止重试；需要管理员明确授权后重新注册")
	}
	if e = BindIdentityServer(a.StateDir, a.Identity, a.Config.Server); e != nil {
		return e
	}
	// Save only the local input. Bootstrap credentials fetched below stay in
	// memory; registered devices reconnect with their independent identity.
	localConfig := a.Config
	if a.bootstrapFetched {
		localConfig.BatchID, localConfig.Token, localConfig.Group = "", "", ""
	}
	if e = SaveConfig(a.StateDir, localConfig); e != nil {
		return e
	}
	defer a.HTTP.CloseIdleConnections()
	delay := time.Duration(rand.Int64N(int64(2 * time.Second)))
	if a.Config.CookieAccountID != "" {
		delay = time.Duration(rand.Int64N(int64(250 * time.Millisecond)))
	}
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(delay):
	}
	backoff := time.Second
	for {
		start := time.Now()
		if !a.Identity.Registered {
			if a.Config.BatchID == "" || a.Config.Token == "" {
				e = a.bootstrap(ctx)
			} else {
				e = nil
			}
			if e == nil {
				e = a.register(ctx)
			}
			if e == nil {
				backoff = time.Second
				continue
			}
		} else {
			e = a.connected(ctx, func() { backoff = time.Second })
		}
		if ctx.Err() != nil {
			a.status("stopped")
			return nil
		}
		var api *APIError
		if errors.As(e, &api) && api.Status == 403 {
			if api.Code == "device_revoked" {
				a.Identity.Revoked = true
				_ = SaveIdentity(a.StateDir, a.Identity)
			}
			a.status(api.Code)
			return e
		}
		if e != nil {
			fmt.Fprintf(os.Stderr, "[%s] Agent连接中断: %v\n", time.Now().UTC().Format(time.RFC3339), e)
		}
		a.status("reconnecting")
		if time.Since(start) > 3*time.Minute {
			backoff = time.Second
		}
		wait := time.Duration(rand.Int64N(int64(backoff) + 1))
		fmt.Fprintf(os.Stderr, "[%s] %.1f秒后重连\n", time.Now().UTC().Format(time.RFC3339), wait.Seconds())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if backoff < 15*time.Second {
			backoff *= 2
			if backoff > 15*time.Second {
				backoff = 15 * time.Second
			}
		}
	}
}
func (a *Agent) status(state string) {
	data, _ := json.Marshal(map[string]any{"device_id": a.Identity.ID, "server": a.Config.Server, "state": state, "at": time.Now().Unix(), "pid": os.Getpid(), "ssh_target": a.Target})
	_ = secure.AtomicFile(filepath.Join(a.StateDir, "status.json"), data, 0600)
}
func (a *Agent) dial(ctx context.Context, path, purpose string) (*websocket.Conn, error) {
	p, e := a.proof(ctx, purpose)
	if e != nil {
		return nil, e
	}
	headers := http.Header{}
	headers.Set("X-AgentSSH-Device", p.DeviceID)
	headers.Set("X-AgentSSH-Nonce", p.Nonce)
	headers.Set("X-AgentSSH-Signature", p.Signature)
	c, res, e := websocket.Dial(ctx, protocol.Endpoint(a.Config.Server, path, true), &websocket.DialOptions{HTTPClient: a.HTTP, HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		if res != nil {
			b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
			res.Body.Close()
			var p struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(b, &p)
			return nil, &APIError{res.StatusCode, p.Code, p.Message}
		}
		return nil, errors.New("WSS连接失败")
	}
	return c, nil
}
func (a *Agent) send(ctx context.Context, c *websocket.Conn, m protocol.Message) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Write(ctx, websocket.MessageText, b)
}
func (a *Agent) connected(parent context.Context, onWelcome func()) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	c, e := a.dial(ctx, "agent/control", "control")
	if e != nil {
		return e
	}
	defer c.CloseNow()
	c.SetReadLimit(protocol.ControlLimit)
	readctx, stop := context.WithTimeout(ctx, 15*time.Second)
	_, b, e := c.Read(readctx)
	stop()
	if e != nil {
		return e
	}
	var hello protocol.Message
	if json.Unmarshal(b, &hello) != nil || hello.Type != "welcome" || hello.Version != protocol.Version || hello.DeviceID != a.Identity.ID {
		return errors.New("控制握手无效")
	}
	a.status("connected")
	meta := a.Metadata()
	if e = a.send(ctx, c, protocol.Message{Type: "metadata", Metadata: &meta}); e != nil {
		return e
	}
	if onWelcome != nil {
		onWelcome()
	}
	fmt.Fprintf(os.Stderr, "[%s] Agent已连接，设备 %s，版本 %s\n", time.Now().UTC().Format(time.RFC3339), a.Identity.ID, protocol.BuildVersion)
	var wg sync.WaitGroup
	defer func() { cancel(); c.CloseNow(); wg.Wait() }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		protocol.KeepAlive(ctx, c, ctx.Done())
	}()
	if a.Config.AutoUser != "" {
		code := "failed"
		if a.Identity.InitApplied {
			code = "ok"
		}
		_ = a.send(ctx, c, protocol.Message{Type: "init_result", Code: code})
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		timer := time.NewTimer(heartbeatDelay())
		defer timer.Stop()
		lastMeta := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				m := protocol.Message{Type: "heartbeat"}
				if time.Since(lastMeta) > 90*time.Second {
					v := a.Metadata()
					m.Metadata = &v
					lastMeta = time.Now()
				}
				if a.send(ctx, c, m) != nil {
					cancel()
					c.CloseNow()
					return
				}
				timer.Reset(heartbeatDelay())
			}
		}
	}()
	for {
		readctx, stop := context.WithTimeout(ctx, protocol.ControlReadTimeout)
		typ, b, e := c.Read(readctx)
		stop()
		if e != nil {
			return e
		}
		if typ != websocket.MessageText {
			return errors.New("控制消息类型无效")
		}
		var m protocol.Message
		if json.Unmarshal(b, &m) != nil {
			return errors.New("控制消息格式无效")
		}
		switch m.Type {
		case "heartbeat_ack":
		case "open_data":
			if m.Generation != hello.Generation || m.SessionID == "" || m.Ticket == "" {
				return errors.New("数据请求绑定无效")
			}
			select {
			case a.dataSlots <- struct{}{}:
				wg.Add(1)
				go func(m protocol.Message) { defer wg.Done(); defer func() { <-a.dataSlots }(); a.forward(ctx, m) }(m)
			default:
				fmt.Fprintln(os.Stderr, "本地SSH会话上限已达")
			}
		default:
			return errors.New("不支持的控制消息")
		}
	}
}
func heartbeatDelay() time.Duration { return time.Duration(15+rand.IntN(6)) * time.Second }
func (a *Agent) forward(parent context.Context, m protocol.Message) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	local, e := dialer.DialContext(ctx, "tcp", a.Target)
	if e != nil {
		return
	}
	defer local.Close()
	ws, e := a.dial(ctx, "agent/data", "data")
	if e != nil {
		return
	}
	defer ws.CloseNow()
	b, _ := json.Marshal(protocol.Message{Type: "data", SessionID: m.SessionID, Generation: m.Generation, Ticket: m.Ticket})
	if e = ws.Write(ctx, websocket.MessageText, b); e != nil {
		return
	}
	stream := protocol.NewStream(ctx, ws)
	defer stream.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(stream, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, stream); done <- struct{}{} }()
	select {
	case <-ctx.Done():
	case <-done:
	}
	cancel()
	local.Close()
	stream.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}
func (a *Agent) Metadata() protocol.Metadata {
	if a.MetadataProvider != nil {
		return a.MetadataProvider()
	}

	host, _ := os.Hostname()
	m := protocol.Metadata{RegistrationName: a.Config.RegistrationName, CookieAccountID: a.Config.CookieAccountID, Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), Version: protocol.BuildVersion, IPs: []string{}}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && !ip.IsLoopback() && len(m.IPs) < 32 {
			m.IPs = append(m.IPs, ip.String())
		}
	}
	if b, e := os.ReadFile("/proc/meminfo"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					n, _ := strconv.ParseUint(fields[1], 10, 64)
					m.Memory = n * 1024
				}
				break
			}
		}
	}
	if b, e := os.ReadFile("/sys/fs/cgroup/memory.max"); e == nil {
		if n, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); e == nil && n < m.Memory {
			m.Memory = n
		}
	}
	c, e := net.DialTimeout("tcp", a.Target, time.Second)
	if e == nil {
		m.SSHReachable = true
		c.Close()
	}
	if a.Config.AutoUser == "" {
		m.SSHInit = "not_requested"
	} else if a.Identity == nil || !a.Identity.Registered {
		m.SSHInit = "pending"
	} else if a.Identity.InitApplied {
		m.SSHInit = "applied"
	} else {
		m.SSHInit = "failed"
	}
	return m
}

// InitializeSSH retries only the explicit local bootstrap policy, never a remote command.
func (a *Agent) InitializeSSH(ctx context.Context) error {
	if a.Config.AutoUser == "" {
		return errors.New("本客户端未包含自动公钥授权策略")
	}
	lock, e := Lock(a.StateDir)
	if e != nil {
		return e
	}
	defer lock.Close()
	a.Identity, e = LoadIdentity(a.StateDir)
	if e != nil {
		return e
	}
	if a.Identity.Revoked {
		return errors.New("设备已撤销，拒绝初始化")
	}
	if e = BindIdentityServer(a.StateDir, a.Identity, a.Config.Server); e != nil {
		return e
	}
	return a.register(ctx)
}
