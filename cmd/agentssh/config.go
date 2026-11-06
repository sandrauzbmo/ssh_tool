package main

import (
	"crypto/x509"
	"errors"
	"os"

	"github.com/sandrauzbmo/ssh_tool/internal/agent"
	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
)

func withServer(c pack.Config, server, caFile string) (pack.Config, error) {
	selected, err := protocol.NormalizeServer(server)
	if err != nil {
		return c, err
	}
	if c.Server != "" {
		previous, err := protocol.NormalizeServer(c.Server)
		if err != nil || previous != selected {
			return c, errors.New("本机配置属于其他控制台；请为不同控制台指定独立--state-dir")
		}
	}
	c.Server = selected
	if caFile != "" {
		info, err := os.Stat(caFile)
		if err != nil {
			return c, err
		}
		if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
			return c, errors.New("CA文件必须是大小受限的普通PEM文件")
		}
		data, err := os.ReadFile(caFile)
		if err != nil {
			return c, err
		}
		c.CA = string(data)
	}
	if c.CA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CA)) {
		return c, errors.New("CA证书无效")
	}
	return c, agent.ValidateConfig(c)
}

// No executable trailer or compiled deployment is consulted. --server is
// required even when local state already records the selected console.
func configuration(state, server, caFile string) (pack.Config, error) {
	if _, err := protocol.NormalizeServer(server); err != nil {
		return pack.Config{}, err
	}
	c, exists, err := agent.LoadConfig(state)
	if err != nil {
		return c, err
	}
	if !exists {
		c.Protocol = protocol.Version
	}
	c, err = withServer(c, server, caFile)
	if err != nil {
		return c, err
	}
	if err = agent.CheckServerBinding(state, c.Server); err != nil {
		return c, err
	}
	return c, nil
}
