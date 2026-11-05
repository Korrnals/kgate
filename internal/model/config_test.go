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
