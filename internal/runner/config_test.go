package runner

import (
	"github.com/mubeng/mubeng/common"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPools(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tier.txt"), []byte("http://127.0.0.1:9000\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pools.json")
	configs := []struct {
		name, data string
		valid      bool
	}{
		{"independent", `{"pools":[{"name":"basic","type":"http","address":"127.0.0.1:8080","file":"tier.txt"},{"name":"premium","type":"socks5","address":"127.0.0.1:1080","file":"tier.txt","method":"random"}]}`, true},
		{"empty", `{"pools":[]}`, false},
		{"unknown field", `{"pool":[]}`, false},
		{"invalid type", `{"pools":[{"name":"x","type":"tcp","address":"127.0.0.1:8080","file":"tier.txt"}]}`, false},
		{"missing file", `{"pools":[{"name":"x","type":"http","address":"127.0.0.1:8080","file":"missing.txt"}]}`, false},
		{"invalid port", `{"pools":[{"name":"x","type":"http","address":"127.0.0.1:0","file":"tier.txt"}]}`, false},
		{"duplicate address", `{"pools":[{"name":"x","type":"http","address":"127.0.0.1:8080","file":"tier.txt"},{"name":"y","type":"socks5","address":"127.0.0.1:8080","file":"tier.txt"}]}`, false},
	}
	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			opt := &common.Options{Config: path, Method: "sequent"}
			err := loadPools(opt)
			if (err == nil) != tc.valid {
				t.Fatalf("loadPools error = %v", err)
			}
			if tc.valid {
				if opt.Pools[0].ProxyManager == opt.Pools[1].SocksProxyManager {
					t.Fatal("pools share manager")
				}
				if opt.Pools[1].SocksMethod != "random" {
					t.Fatal("method override lost")
				}
				if opt.Pools[0].File != filepath.Join(dir, "tier.txt") {
					t.Fatal("relative path not resolved")
				}
			}
		})
	}
}
