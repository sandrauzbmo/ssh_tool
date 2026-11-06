package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

var accountName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}\$?$`)

func ListAuthorizedKeys(account string) ([]map[string]string, error) {
	if !accountName.MatchString(account) {
		return nil, errors.New("账户无效")
	}
	u, e := user.Lookup(account)
	if e != nil {
		return nil, e
	}
	uid, _ := strconv.Atoi(u.Uid)
	if os.Geteuid() != 0 && os.Geteuid() != uid {
		return nil, errors.New("无权读取此账户")
	}
	fd, e := unix.Open(filepath.Join(u.HomeDir, ".ssh"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	keyfd, e := unix.Openat(fd, "authorized_keys", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(keyfd), "authorized_keys")
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if e != nil || len(b) > 1024*1024 {
		return nil, errors.New("公钥文件过大或读取失败")
	}
	out := []map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, comment, _, _, e := ssh.ParseAuthorizedKey([]byte(line))
		if e == nil && strings.HasPrefix(comment, "agentssh:") {
			out = append(out, map[string]string{"device_id": strings.TrimPrefix(comment, "agentssh:"), "fingerprint": ssh.FingerprintSHA256(key)})
		}
	}
	return out, nil
}

// UpdateAuthorizedKey is a local, explicit bootstrap/cleanup operation, never a control-channel RPC.
func UpdateAuthorizedKey(account, id, public string, remove bool) error {
	if !accountName.MatchString(account) || len(id) < 16 || strings.ContainsAny(id, " \t\n\r") {
		return errors.New("账户或设备ID无效")
	}
	u, e := user.Lookup(account)
	if e != nil {
		return errors.New("目标系统账户不存在")
	}
	uid, e := strconv.Atoi(u.Uid)
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(u.Gid)
	if e != nil {
		return e
	}
	if os.Geteuid() != 0 && os.Geteuid() != uid {
		return errors.New("当前用户无权配置该SSH账户")
	}
	home, e := os.Lstat(u.HomeDir)
	if e != nil || !home.IsDir() || home.Mode()&os.ModeSymlink != 0 {
		return errors.New("账户主目录无效或为符号链接")
	}
	path := filepath.Join(u.HomeDir, ".ssh")
	if e = os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return errors.New(".ssh不能是符号链接")
	}
	defer unix.Close(fd)
	if os.Geteuid() == 0 {
		if e = unix.Fchown(fd, uid, gid); e != nil {
			return e
		}
	}
	if e = unix.Fchmod(fd, 0700); e != nil {
		return e
	}
	lock, e := unix.Openat(fd, ".agentssh.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	defer unix.Close(lock)
	if e = unix.Flock(lock, unix.LOCK_EX); e != nil {
		return e
	}
	defer unix.Flock(lock, unix.LOCK_UN)
	if os.Geteuid() == 0 {
		if e = unix.Fchown(lock, uid, gid); e != nil {
			return e
		}
	}
	var old []byte
	existing, e := unix.Openat(fd, "authorized_keys", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e == nil {
		file := os.NewFile(uintptr(existing), "authorized_keys")
		var st unix.Stat_t
		if e = unix.Fstat(existing, &st); e != nil {
			file.Close()
			return e
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != uid {
			file.Close()
			return errors.New("authorized_keys必须是该账户拥有且无硬链接的普通文件")
		}
		old, e = io.ReadAll(io.LimitReader(file, 1024*1024+1))
		file.Close()
		if e != nil || len(old) > 1024*1024 {
			return errors.New("authorized_keys超过安全处理上限")
		}
	} else if e != unix.ENOENT {
		return errors.New("无法安全读取authorized_keys")
	}
	marker := "agentssh:" + id
	lines := strings.Split(string(old), "\n")
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if strings.HasSuffix(strings.TrimSpace(line), " "+marker) {
			continue
		}
		out = append(out, line)
	}
	result := strings.Join(out, "\n")
	if !remove {
		key, _, _, _, e := ssh.ParseAuthorizedKey([]byte(public))
		if e != nil {
			return errors.New("SSH公钥无效")
		}
		if result != "" && !strings.HasSuffix(result, "\n") {
			result += "\n"
		}
		result += "restrict,pty " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + marker + "\n"
	}
	if result == string(old) {
		return nil
	}
	temp := ".agentssh-" + protocol.Random(12)
	dest, e := unix.Openat(fd, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	defer unix.Unlinkat(fd, temp, 0)
	file := os.NewFile(uintptr(dest), temp)
	if os.Geteuid() == 0 {
		e = unix.Fchown(dest, uid, gid)
	}
	if e == nil {
		_, e = file.WriteString(result)
	}
	if e == nil {
		e = file.Sync()
	}
	if closeErr := file.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = unix.Renameat(fd, temp, fd, "authorized_keys"); e != nil {
		return e
	}
	if e = unix.Fsync(fd); e != nil {
		return e
	}
	fmt.Fprintf(os.Stderr, "已%s本项目公钥：账户=%s 设备=%s\n", map[bool]string{true: "移除", false: "配置"}[remove], account, id)
	return nil
}
