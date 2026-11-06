package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
	"github.com/sandrauzbmo/ssh_tool/internal/secure"
)

func readPrivateJSON(path string, value any) (bool, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 65536 {
		return false, errors.New("本机状态必须是大小受限的0600普通文件")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if err = json.Unmarshal(b, value); err != nil {
		return false, errors.New("本机状态格式无效，拒绝自动覆盖")
	}
	return true, nil
}

func LoadConfig(state string) (pack.Config, bool, error) {
	var c pack.Config
	exists, err := readPrivateJSON(filepath.Join(state, "config.json"), &c)
	return c, exists, err
}

func SaveConfig(state string, c pack.Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return secure.AtomicFile(filepath.Join(state, "config.json"), b, 0600)
}

// CheckServerBinding never changes state or sends a proof to another console.
// Legacy identities may be adopted only when a matching local record exists.
func CheckServerBinding(state, server string) error {
	selected, err := protocol.NormalizeServer(server)
	if err != nil {
		return err
	}
	var identity struct {
		ID, Server string
		Registered bool
	}
	exists, err := readPrivateJSON(filepath.Join(state, "identity.json"), &identity)
	if err != nil || !exists {
		return err
	}
	conflict := errors.New("此状态目录属于其他控制台；请为不同控制台指定独立--state-dir，不会覆盖原身份")
	if identity.Server != "" {
		bound, e := protocol.NormalizeServer(identity.Server)
		if e != nil || bound != selected {
			return conflict
		}
		return nil
	}
	if !identity.Registered {
		return nil
	}
	known := false
	if c, exists, e := LoadConfig(state); e != nil {
		return e
	} else if exists && c.Server != "" {
		bound, e := protocol.NormalizeServer(c.Server)
		if e != nil || bound != selected {
			return conflict
		}
		known = true
	}
	var status struct {
		DeviceID string `json:"device_id"`
		Server   string `json:"server"`
	}
	if exists, e := readPrivateJSON(filepath.Join(state, "status.json"), &status); e != nil {
		return e
	} else if exists && status.Server != "" {
		bound, e := protocol.NormalizeServer(status.Server)
		if e != nil || bound != selected || status.DeviceID != identity.ID {
			return conflict
		}
		known = true
	}
	if !known {
		return errors.New("旧身份缺少控制台绑定记录；请恢复原config.json或status.json，或使用独立--state-dir，原身份不会重置")
	}
	return nil
}

func BindIdentityServer(state string, identity *Identity, server string) error {
	if err := CheckServerBinding(state, server); err != nil {
		return err
	}
	canonical, err := protocol.NormalizeServer(server)
	if err != nil {
		return err
	}
	if identity.Server == canonical {
		return nil
	}
	identity.Server = canonical
	return SaveIdentity(state, identity)
}

func (a *Agent) bootstrap(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", protocol.Endpoint(a.Config.Server, "agent/bootstrap", false), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := a.HTTP.Do(req)
	if err != nil {
		return errors.New("无法通过可信HTTPS获取注册设置；请用doctor检查网络，私有CA请通过--ca-file提供")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		message := "控制台未开放可用的自动注册入口；请联系管理员，或通过configure导入本机配置"
		return &APIError{Status: res.StatusCode, Code: "bootstrap_unavailable", Message: message}
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(b) > 65536 {
		return errors.New("自动注册响应过大或读取失败")
	}
	var config protocol.BootstrapResponse
	if json.Unmarshal(b, &config) != nil || config.Protocol != protocol.Version || len(config.BatchID) < 1 || len(config.BatchID) > 64 || len(config.Token) < 1 || len(config.Token) > 256 || len(config.Group) > 128 {
		return errors.New("控制台返回无效的自动注册设置")
	}
	a.Config.BatchID, a.Config.Token, a.Config.Group = config.BatchID, config.Token, config.Group
	a.bootstrapFetched = true
	// Remote enrollment cannot authorize modifying local authorized_keys.
	return nil
}
