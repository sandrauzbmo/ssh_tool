package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
	"github.com/sandrauzbmo/ssh_tool/internal/secure"
)

type Identity struct {
	Server      string `json:"server,omitempty"`
	ID          string `json:"id"`
	PrivateKey  string `json:"private_key"`
	Registered  bool   `json:"registered"`
	Revoked     bool   `json:"revoked"`
	InitApplied bool   `json:"init_applied"`
	InitUser    string `json:"init_user,omitempty"`
}

func DefaultState() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "agentssh")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local/state/agentssh")
}
func Lock(dir string) (*os.File, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("状态目录不能是符号链接")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(filepath.Join(dir, ".lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "agentssh lock")
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("同一状态目录已有Agent运行")
	}
	return f, nil
}
func LoadIdentity(dir string) (*Identity, error) {
	path := filepath.Join(dir, "identity.json")
	st, e := os.Lstat(path)
	if os.IsNotExist(e) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		i := &Identity{ID: protocol.Random(24), PrivateKey: base64.RawStdEncoding.EncodeToString(key)}
		return i, SaveIdentity(dir, i)
	}
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("身份文件必须是0600普通文件")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var i Identity
	if json.Unmarshal(b, &i) != nil || len(i.ID) < 16 {
		return nil, errors.New("身份文件损坏，请人工处理，禁止自动重置")
	}
	key, e := base64.RawStdEncoding.DecodeString(i.PrivateKey)
	if e != nil || len(key) != 64 {
		return nil, errors.New("设备私钥无效")
	}
	return &i, nil
}
func SaveIdentity(dir string, i *Identity) error {
	b, e := json.Marshal(i)
	if e != nil {
		return e
	}
	return secure.AtomicFile(filepath.Join(dir, "identity.json"), b, 0600)
}
func (i *Identity) Key() ed25519.PrivateKey {
	b, _ := base64.RawStdEncoding.DecodeString(i.PrivateKey)
	return ed25519.PrivateKey(b)
}
func (i *Identity) Public() string {
	return base64.RawStdEncoding.EncodeToString(i.Key().Public().(ed25519.PublicKey))
}
