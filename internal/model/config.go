package model

import (
	"os"
	"time"
)

// Config — единый файл конфигурации kgate (kgate.yaml).
// Одна и та же залита на роутер и лежит на ноутбуке: клиенту/деплойеру важны
// секции host/api, демону на роутере — секции api/daemon.
type Config struct {
	Host    string `yaml:"host"`     // адрес роутера (клиент/деплой)
	SSHPort int    `yaml:"ssh_port"` // ssh для деплоя
	SSHUser string `yaml:"ssh_user"`
	SSHKey  string `yaml:"ssh_key"`

	API struct {
		Port  int    `yaml:"port"`  // порт демона на роутере (mTLS)
		CA    string `yaml:"ca"`    // локальные пути клиента
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
		Interval      string `yaml:"supervisor_interval"` // тик супервизора
		BootAutoup    bool   `yaml:"boot_autoup"`         // поднимать Proxy0 при старте
		AutoupDelay   string `yaml:"autoup_delay"`
		APIListen     string `yaml:"api_listen"` // ":9443"
		WebRoot       string `yaml:"web_root"`   // CA/серт сервера на роутере
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

// Load читает yaml; отсутствующий файл = дефолты.
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
