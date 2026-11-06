package agent

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/sandrauzbmo/ssh_tool/internal/secure"
)

func MigrateState(source, target string, uid, gid int) error {
	identity, e := LoadIdentity(source)
	if e != nil {
		return e
	}
	if !identity.Registered {
		return errors.New("迁移前需要完成设备注册")
	}
	if e = os.MkdirAll(target, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(target)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("目标状态目录无效或为符号链接")
	}
	entries, e := os.ReadDir(target)
	if e != nil {
		return e
	}
	_, idErr := os.Lstat(filepath.Join(target, "identity.json"))
	_, markerErr := os.Lstat(filepath.Join(target, ".managed-by-agentssh"))
	if len(entries) > 0 && os.IsNotExist(idErr) && os.IsNotExist(markerErr) {
		return errors.New("目标目录含非本项目文件，拒绝覆盖")
	}
	if idErr == nil {
		old, e := LoadIdentity(target)
		if e != nil || old.ID != identity.ID {
			return errors.New("目标目录已有不同设备身份，拒绝覆盖")
		}
	}
	if e = SaveIdentity(target, identity); e != nil {
		return e
	}
	config := filepath.Join(source, "config.json")
	if st, e := os.Lstat(config); e == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return errors.New("配置必须为0600普通文件")
		}
		b, e := os.ReadFile(config)
		if e != nil {
			return e
		}
		if e = secure.AtomicFile(filepath.Join(target, "config.json"), b, 0600); e != nil {
			return e
		}
	}
	if e = secure.AtomicFile(filepath.Join(target, ".managed-by-agentssh"), []byte("AgentSSH identity state\n"), 0600); e != nil {
		return e
	}
	if os.Geteuid() == 0 {
		if e = os.Chown(target, uid, gid); e != nil {
			return e
		}
		for _, name := range []string{"identity.json", "config.json", ".lock", ".managed-by-agentssh"} {
			p := filepath.Join(target, name)
			if _, e = os.Lstat(p); e == nil {
				if e = os.Chown(p, uid, gid); e != nil {
					return e
				}
			}
		}
	}
	return os.Chmod(target, 0700)
}
