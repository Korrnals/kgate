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
