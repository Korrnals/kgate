// Self-managed ssh keys: kgate generates its own ed25519 pair and installs
// the public key on the router (append-only) using a one-time password —
// the operator never deals with key files by hand.
package deploy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"kgate/internal/model"
)

// ensureKeyPair makes sure a private key exists at path (generating a fresh
// ed25519 pair alongside `path.pub` when missing) and returns the signer.
func ensureKeyPair(path string) (ssh.Signer, error) {
	if _, err := os.Stat(path); err == nil {
		key, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ssh.ParsePrivateKey(key)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	// OpenSSH-format private key (openssh-key-v1), like ssh-keygen produces
	pemBlock, err := ssh.MarshalPrivateKey(signer, "kgate")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, pemBlock); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := os.WriteFile(path+".pub", []byte(pubLine+"\n"), 0o644); err != nil {
		return nil, err
	}
	fmt.Printf("  [OK] сгенерирована ssh-пара: %s (+ .pub)\n", path)
	return signer, nil
}

// installPubKey appends the operator public key to the router's
// authorized_keys using a one-time password session. Append-only: existing
// keys are never touched. The one-time password session targets a LAN router;
// subsequent connections are key-authenticated and host-key checked.
func installPubKey(cfg *model.Config, signer ssh.Signer, password string) error {
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", cfg.Host, cfg.SSHPort), &ssh.ClientConfig{
		User: cfg.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
				return []string{password}, nil
			}),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil // one-time password session on a LAN router; key auth is verified on the key path
		},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	script := fmt.Sprintf(`mkdir -p /opt/etc/ssh && touch /opt/etc/ssh/authorized_keys
grep -qF %q /opt/etc/ssh/authorized_keys || echo %q >> /opt/etc/ssh/authorized_keys
chmod 600 /opt/etc/ssh/authorized_keys
echo key-installed`, pub, pub)
	out, err := sess.CombinedOutput(script)
	if err != nil || !strings.Contains(string(out), "key-installed") {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// installPubKeyViaFirmwareSftp bootstraps through the FIRMWARE ssh (port 22,
// KeeneticOS users with «Командная строка» + SFTP): appends the operator
// public key to /opt/etc/ssh/authorized_keys. Works even when the Entware
// sshd keys are clobbered/missing — the firmware authenticates its own users
// independently of Entware.
func installPubKeyViaFirmwareSftp(cfg *model.Config, adminLogin, adminPassword, pub string) error {
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", cfg.Host), &ssh.ClientConfig{
		User: adminLogin,
		Auth: []ssh.AuthMethod{
			ssh.Password(adminPassword),
			ssh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
				return []string{adminPassword}, nil
			}),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil // one-time LAN session; the operator key is appended, not replaced
		},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	sftpCli, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp: %w", err)
	}
	defer sftpCli.Close()
	const keysPath = "/opt/etc/ssh/authorized_keys"
	existing, readErr := sftpRead(sftpCli, keysPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		// never-clobber: unknown read state must NEVER reach the O_TRUNC write
		// (wave-1 review MINOR-2 — the v1.4.1 lockout class)
		return fmt.Errorf("чтение %s не удалось (%v) — не рискую перезаписью; отмена", keysPath, readErr)
	}
	if readErr == nil && strings.Contains(existing, pub) {
		return nil // already installed
	}
	content := strings.TrimRight(existing, "\n")
	if content != "" {
		content += "\n"
	}
	content += pub + "\n"
	wf, err := sftpCli.OpenFile(keysPath, os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		wf, err = sftpCli.OpenFile(keysPath, os.O_WRONLY|os.O_CREATE)
		if err != nil {
			return fmt.Errorf("открыть %s: %w", keysPath, err)
		}
	}
	if _, err := wf.Write([]byte(content)); err != nil {
		wf.Close()
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	_ = sftpCli.Chmod(keysPath, 0o600)
	return nil
}

func sftpRead(cli *sftp.Client, path string) (string, error) {
	f, err := cli.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	return string(b), err
}
