package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const Version = 1
const ControlLimit = 32768
const DataLimit = 65536
const DataChunk = 16384
const ControlReadTimeout = 75 * time.Second
const KeepAliveInterval = 15 * time.Second

var BuildVersion = "0.2.0"

// BootstrapResponse contains enrollment data obtained from the selected HTTPS
// console. It cannot change the selected console, CA trust or local SSH policy.
type BootstrapResponse struct {
	Protocol int    `json:"protocol"`
	BatchID  string `json:"batch_id"`
	Token    string `json:"token"`
	Group    string `json:"group"`
}

func NormalizeServer(raw string) (string, error) {
	invalid := errors.New("请使用--server指定有效HTTPS控制台地址，不得包含用户名、查询参数或片段")
	if raw == "" || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return "", invalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.Opaque != "" {
		return "", invalid
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", invalid
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", invalid
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u.Host = host
	if port != "" && port != "443" {
		u.Host += ":" + port
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	return u.String(), nil
}

type Metadata struct {
	SSHInit      string   `json:"ssh_init"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	IPs          []string `json:"ips"`
	CPUs         int      `json:"cpus"`
	Memory       uint64   `json:"memory"`
	Version      string   `json:"version"`
	SSHReachable bool     `json:"ssh_reachable"`
}
type Message struct {
	Type       string    `json:"type"`
	Version    int       `json:"version,omitempty"`
	RequestID  string    `json:"request_id,omitempty"`
	DeviceID   string    `json:"device_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	Generation string    `json:"generation,omitempty"`
	Ticket     string    `json:"ticket,omitempty"`
	Metadata   *Metadata `json:"metadata,omitempty"`
	Code       string    `json:"code,omitempty"`
}
type Proof struct {
	DeviceID  string `json:"device_id"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}
type RegisterRequest struct {
	Proof
	PublicKey string   `json:"public_key"`
	BatchID   string   `json:"batch_id"`
	Token     string   `json:"token"`
	Metadata  Metadata `json:"metadata"`
}
type RegisterResponse struct {
	DeviceID string `json:"device_id"`
	InitUser string `json:"init_user,omitempty"`
	InitKey  string `json:"init_key,omitempty"`
}

func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func ProofBytes(purpose, id, nonce string) []byte {
	b, _ := json.Marshal([]any{"agentssh", Version, purpose, id, nonce})
	return b
}
func Sign(key ed25519.PrivateKey, purpose, id, nonce string) string {
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, ProofBytes(purpose, id, nonce)))
}
func Verify(pub string, p Proof, purpose string) bool {
	k, e := base64.RawStdEncoding.DecodeString(pub)
	if e != nil || len(k) != ed25519.PublicKeySize {
		return false
	}
	sig, e := base64.RawStdEncoding.DecodeString(p.Signature)
	return e == nil && ed25519.Verify(k, ProofBytes(purpose, p.DeviceID, p.Nonce), sig)
}
func ValidateTarget(target string) error {
	host, port, e := net.SplitHostPort(target)
	if e != nil {
		return errors.New("SSH目标必须是回环IP和端口")
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || p < 1 || p > 65535 {
		return errors.New("仅允许回环SSH目标")
	}
	return nil
}
func Endpoint(base, path string, ws bool) string {
	u, e := url.Parse(base)
	if e != nil {
		return ""
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + strings.TrimPrefix(path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	if ws {
		if u.Scheme == "https" {
			u.Scheme = "wss"
		} else {
			u.Scheme = "ws"
		}
	}
	return u.String()
}
