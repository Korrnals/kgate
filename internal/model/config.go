package model

import (
	"os"
	"time"
)

// Config is the single kgate configuration file (kgate.yaml).
// The same file lives on the router and on the operator workstation:
// the client/deployer read the host/api sections, the daemon on the
// router reads the api/daemon sections.
type Config struct {
	Host     string `yaml:"host"`      // router address (client/deployer)
	ServerIP string `yaml:"server_ip"` // hy2 exit server IP (used for the ndm route pin)
	SSHPort int    `yaml:"ssh_port"` // ssh used by the deployer
	SSHUser string `yaml:"ssh_user"`
	SSHKey  string `yaml:"ssh_key"`

	API struct {
		Port  int    `yaml:"port"`  // daemon mTLS API port on the router
		CA    string `yaml:"ca"`    // local client cert paths
		Cert  string `yaml:"cert"`
		Key   string `yaml:"key"`
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
		c.SSHKey = os.Getenv("HOME") + "/.ssh/id_ed25519"
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
	return c, nil
}

func Dur(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
