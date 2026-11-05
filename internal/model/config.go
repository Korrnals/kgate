package model

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the single kgate configuration file (kgate.yaml).
// The same file lives on the router and on the operator workstation:
// the client/deployer read the host/api sections, the daemon on the
// router reads the api/daemon sections.
type Config struct {
	Host     string `yaml:"host"`      // router address (client/deployer)
	ServerIP string `yaml:"server_ip"` // hy2 exit server IP (used for the ndm route pin)
	SSHPort  int    `yaml:"ssh_port"`  // ssh used by the deployer
	SSHUser  string `yaml:"ssh_user"`
	SSHKey   string `yaml:"ssh_key"`

	API struct {
		Port int    `yaml:"port"` // daemon mTLS API port on the router
		CA   string `yaml:"ca"`   // local client cert paths
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"api"`

	Daemon struct {
		SingBoxBin    string `yaml:"singbox_bin"`
		SingBoxConfig string `yaml:"singbox_config"`
		SingBoxLog    string `yaml:"singbox_log"`
		XrayBin       string `yaml:"xray_bin"`
		XrayConfig    string `yaml:"xray_config"`
		XrayLog       string `yaml:"xray_log"`
		RelayListen   string `yaml:"relay_listen"`
		RelayUpstream string `yaml:"relay_upstream"`
		RlimitNofile  uint64 `yaml:"rlimit_nofile"`
		Interval      string `yaml:"supervisor_interval"` // supervisor tick
		BootAutoup    bool   `yaml:"boot_autoup"`         // raise Proxy0 after startup
		AutoupDelay   string `yaml:"autoup_delay"`
		APIListen     string `yaml:"api_listen"` // ":9443"
		WebRoot       string `yaml:"web_root"`   // server CA/certs on the router
		Log           string `yaml:"log"`
	} `yaml:"daemon"`
}

func (c *Config) fillDefaults() {
	if c.Host == "" {
		c.Host = "192.168.1.1"
	}
	if c.SSHPort == 0 {
		c.SSHPort = 222
	}
	if c.SSHUser == "" {
		c.SSHUser = "root"
	}
	if c.SSHKey == "" {
		c.SSHKey = os.Getenv("HOME") + "/.ssh/kgate-ed25519"
	}
	if c.API.Port == 0 {
		c.API.Port = 9443
	}
	home := os.Getenv("HOME") + "/.kgate"
	if c.API.CA == "" {
		c.API.CA = home + "/ca.crt"
	}
	if c.API.Cert == "" {
		c.API.Cert = home + "/client.crt"
	}
	if c.API.Key == "" {
		c.API.Key = home + "/client.key"
	}
	d := &c.Daemon
	if d.SingBoxBin == "" {
		d.SingBoxBin = "/opt/sbin/sing-box"
	}
	if d.SingBoxConfig == "" {
		d.SingBoxConfig = "/opt/etc/sing-box/config.json"
	}
	if d.SingBoxLog == "" {
		d.SingBoxLog = "/opt/var/log/singbox.log"
	}
	if d.XrayBin == "" {
		d.XrayBin = "/opt/sbin/xray"
	}
	if d.XrayConfig == "" {
		d.XrayConfig = "/opt/etc/xray/config.json"
	}
	if d.XrayLog == "" {
		d.XrayLog = "/opt/var/log/xray.log"
	}
	if d.RelayListen == "" {
		d.RelayListen = "127.0.0.1:1090"
	}
	if d.RelayUpstream == "" {
		d.RelayUpstream = "127.0.0.1:1080"
	}
	if d.RlimitNofile == 0 {
		d.RlimitNofile = 8192
	}
	if d.Interval == "" {
		d.Interval = "15s"
	}
	if d.AutoupDelay == "" {
		d.AutoupDelay = "25s"
	}
	if d.APIListen == "" {
		d.APIListen = ":9443"
	}
	if d.WebRoot == "" {
		d.WebRoot = "/opt/etc/kgate"
	}
	if d.Log == "" {
		d.Log = "/opt/var/log/kgate.log"
	}
}

// Load reads the YAML config; a missing file yields defaults.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			if err := yamlUnmarshal(b, c); err != nil {
				return nil, err
			}
		}
	}
	c.fillDefaults()
	applyEnv(c)
	expandHomes(c)
	return c, nil
}

// expandHome rewrites a leading ~ (or ~/) with the user's home directory:
// yaml/env values arrive as literals and os.ReadFile does not expand them
// (the shipped template uses ~/.kgate/... — found by the full
// destroy→config create→deploy E2E).
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
		}
	}
	return p
}

// expandHomes expands ~ in the client-side file paths after all config
// sources (yaml > defaults > env) have been merged.
func expandHomes(c *Config) {
	c.SSHKey = expandHome(c.SSHKey)
	c.API.CA = expandHome(c.API.CA)
	c.API.Cert = expandHome(c.API.Cert)
	c.API.Key = expandHome(c.API.Key)
}

// applyEnv применяет переменные окружения KGATE_* поверх yaml.
// Приоритет: env > yaml > встроенные дефолты. Именование зеркалит yaml-пути.
func applyEnv(c *Config) {
	envStr := func(key string, dst *string) {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}
	envInt := func(key string, dst *int) {
		if v := os.Getenv(key); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	envBool := func(key string, dst *bool) {
		if v := os.Getenv(key); v != "" {
			*dst = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
		}
	}

	envStr("KGATE_HOST", &c.Host)
	envStr("KGATE_SERVER_IP", &c.ServerIP)
	envInt("KGATE_SSH_PORT", &c.SSHPort)
	envStr("KGATE_SSH_USER", &c.SSHUser)
	envStr("KGATE_SSH_KEY", &c.SSHKey)

	envInt("KGATE_API_PORT", &c.API.Port)
	envStr("KGATE_API_CA", &c.API.CA)
	envStr("KGATE_API_CERT", &c.API.Cert)
	envStr("KGATE_API_KEY", &c.API.Key)

	envStr("KGATE_DAEMON_SINGBOX_BIN", &c.Daemon.SingBoxBin)
	envStr("KGATE_DAEMON_SINGBOX_CONFIG", &c.Daemon.SingBoxConfig)
	envStr("KGATE_DAEMON_SINGBOX_LOG", &c.Daemon.SingBoxLog)
	envStr("KGATE_DAEMON_RELAY_LISTEN", &c.Daemon.RelayListen)
	envStr("KGATE_DAEMON_RELAY_UPSTREAM", &c.Daemon.RelayUpstream)
	envStr("KGATE_DAEMON_API_LISTEN", &c.Daemon.APIListen)
	envStr("KGATE_DAEMON_WEB_ROOT", &c.Daemon.WebRoot)
	envStr("KGATE_DAEMON_LOG", &c.Daemon.Log)
	if v := os.Getenv("KGATE_DAEMON_RLIMIT_NOFILE"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			c.Daemon.RlimitNofile = n
		}
	}
	envBool("KGATE_DAEMON_BOOT_AUTOUP", &c.Daemon.BootAutoup)
}

func Dur(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
