package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mubeng/mubeng/common"
	"github.com/mubeng/mubeng/internal/proxymanager"
)

// PoolConfig assigns an independent upstream file to a listener.
type PoolConfig struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Address string `json:"address"`
	File    string `json:"file"`
	Method  string `json:"method"`
}

func loadPools(opt *common.Options) error {
	if opt.Check || opt.Daemon || opt.Address != "" || opt.SocksAddress != "" || opt.File != "" || opt.SocksFile != "" {
		return fmt.Errorf("--config cannot be combined with check, daemon, listener/file flags")
	}
	if opt.Sticky && opt.Auth != "" {
		return fmt.Errorf("-sticky cannot be combined with -A/--auth")
	}
	if opt.Auth != "" && len(strings.SplitN(opt.Auth, ":", 2)) != 2 {
		return fmt.Errorf("invalid proxy authorization format")
	}
	f, err := os.Open(opt.Config)
	if err != nil {
		return err
	}
	defer f.Close()
	var config struct {
		Pools []PoolConfig `json:"pools"`
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("config must contain one JSON object")
	}
	if len(config.Pools) == 0 {
		return fmt.Errorf("config has no pools")
	}
	names, addresses := map[string]bool{}, map[string]bool{}
	for _, pool := range config.Pools {
		if pool.Name == "" || names[pool.Name] {
			return fmt.Errorf("pool names must be nonempty and unique: %q", pool.Name)
		}
		names[pool.Name] = true
		if pool.Type != "http" && pool.Type != "socks5" {
			return fmt.Errorf("pool %s: type must be http or socks5", pool.Name)
		}
		_, port, err := net.SplitHostPort(pool.Address)
		if err != nil {
			return fmt.Errorf("pool %s: invalid address: %w", pool.Name, err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("pool %s: invalid port", pool.Name)
		}
		if addresses[pool.Address] {
			return fmt.Errorf("duplicate listener address %s", pool.Address)
		}
		addresses[pool.Address] = true
		if pool.File == "" {
			return fmt.Errorf("pool %s: file is required", pool.Name)
		}
		if !filepath.IsAbs(pool.File) {
			pool.File = filepath.Join(filepath.Dir(opt.Config), pool.File)
		}
		pool.File, err = filepath.Abs(pool.File)
		if err != nil {
			return err
		}
		manager, err := proxymanager.New(pool.File)
		if err != nil {
			return fmt.Errorf("pool %s: %w", pool.Name, err)
		}
		child := *opt
		child.PoolName = pool.Name
		child.Config = ""
		child.Pools = nil
		child.File = pool.File
		child.ProxyManager = manager
		child.Method = pool.Method
		if child.Method == "" {
			child.Method = opt.Method
		}
		if child.Method != "random" && child.Method != "sequent" {
			return fmt.Errorf("pool %s: unknown method %q", pool.Name, child.Method)
		}
		if pool.Type == "http" {
			child.Address = pool.Address
		} else {
			if opt.Auth != "" {
				return fmt.Errorf("pool %s: SOCKS5 does not support --auth", pool.Name)
			}
			child.SocksAddress = pool.Address
			child.SocksFile = pool.File
			child.SocksProxyManager = manager
			child.SocksMethod = child.Method
		}
		opt.Pools = append(opt.Pools, &child)
	}
	return nil
}
