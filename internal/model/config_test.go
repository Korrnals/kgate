package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHomesTildePaths(t *testing.T) {
	home, _ := os.UserHomeDir()
	c := &Config{}
	c.API.CA = "~/.kgate/ca.crt"
	c.API.Cert = "~/x/client.crt"
	c.SSHKey = "~/.ssh/k"
	expandHomes(c)
	if c.API.CA != filepath.Join(home, ".kgate", "ca.crt") {
		t.Fatalf("CA=%q", c.API.CA)
	}
	if c.API.Cert != filepath.Join(home, "x", "client.crt") {
		t.Fatalf("Cert=%q", c.API.Cert)
	}
	if c.SSHKey != filepath.Join(home, ".ssh", "k") {
		t.Fatalf("SSHKey=%q", c.SSHKey)
	}
}

func TestExpandHomesLeavesAbsolute(t *testing.T) {
	c := &Config{}
	c.API.CA = "/opt/etc/kgate/ca.crt"
	c.SSHKey = "/root/.ssh/k"
	expandHomes(c)
	if c.API.CA != "/opt/etc/kgate/ca.crt" || c.SSHKey != "/root/.ssh/k" {
		t.Fatalf("absolute paths must not change: %q %q", c.API.CA, c.SSHKey)
	}
}

// integration: the v1.3.1 regression class — a tilde path arriving via yaml
// AND via env must be expanded AFTER all sources merge (Load order).
func TestLoadExpandsTildeFromYamlAndEnv(t *testing.T) {
	home, _ := os.UserHomeDir()
	yamlPath := filepath.Join(t.TempDir(), "kgate.yaml")
	err := os.WriteFile(yamlPath, []byte("ssh_key: ~/from-yaml\napi:\n  ca: ~/.kgate/ca.crt\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KGATE_SSH_KEY", "~/from-env")
	c, err := Load(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.SSHKey != filepath.Join(home, "from-env") {
		t.Fatalf("env tilde not expanded: %q", c.SSHKey)
	}
	if c.API.CA != filepath.Join(home, ".kgate", "ca.crt") {
		t.Fatalf("yaml tilde not expanded: %q", c.API.CA)
	}
}

// 1.8.0: секция policies парсится из yaml; пустая секция валидна.
func TestLoadPoliciesSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kgate.yaml")
	body := `
policies:
  segments:
    Home: VPN
    Bridge2: NO-VPN
  devices:
    - mac: "54:AE:BC:9C:DE:BF"
      policy: NO-VPN
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Policies.Segments["Home"] != "VPN" || c.Policies.Segments["Bridge2"] != "NO-VPN" {
		t.Fatalf("segments = %v", c.Policies.Segments)
	}
	if len(c.Policies.Devices) != 1 || c.Policies.Devices[0].MAC != "54:AE:BC:9C:DE:BF" || c.Policies.Devices[0].Policy != "NO-VPN" {
		t.Fatalf("devices = %+v", c.Policies.Devices)
	}
	if err := c.Policies.Validate(); err != nil {
		t.Fatalf("валидная декларация отклонена: %v", err)
	}
}

// Конфиг без секции policies — пустая декларация (валидно, fail-safe прямой дефолт).
func TestLoadWithoutPoliciesSection(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Policies.Segments) != 0 || len(c.Policies.Devices) != 0 {
		t.Fatalf("ожидалась пустая декларация: %+v", c.Policies)
	}
	if err := c.Policies.Validate(); err != nil {
		t.Fatalf("пустая декларация отклонена: %v", err)
	}
}

// panel-секция веб-панели (v1.9.0): парсинг + дефолты + env.
func TestLoadPanelSection(t *testing.T) {
	f := filepath.Join(t.TempDir(), "kgate.yaml")
	if err := os.WriteFile(f, []byte("panel:\n  password: secret\n  port: 9444\n  return_url: http://10.0.0.1/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if c.Panel.Password != "secret" || c.Panel.Port != 9444 || c.Panel.ReturnURL != "http://10.0.0.1/" {
		t.Fatalf("panel = %+v", c.Panel)
	}
	// пустая секция/нет секции: панель off, но дефолты на месте
	c2, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c2.Panel.Password != "" || c2.Panel.Port != 8443 || c2.Panel.ReturnURL != "http://192.168.1.1/" {
		t.Fatalf("panel defaults = %+v", c2.Panel)
	}
	// env перекрывает yaml
	t.Setenv("KGATE_PANEL_PORT", "9000")
	t.Setenv("KGATE_PANEL_PASSWORD", "env-pw")
	c3, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if c3.Panel.Port != 9000 || c3.Panel.Password != "env-pw" {
		t.Fatalf("panel env = %+v", c3.Panel)
	}
}
