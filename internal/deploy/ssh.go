// Pure-Go ssh transport for the deployer: the workstation does not need an
// ssh(1) binary (a bare Windows box without OpenSSH works too). Key auth
// only, host keys verified TOFU-style (accept-new) against ~/.ssh/known_hosts
// — a saved key mismatch fails loud instead of silently trusting.
package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"kgate/internal/model"
)

type sshRunner struct {
	cfg    *model.Config
	client *ssh.Client
}

func newSSHRunner(c *model.Config) *sshRunner { return &sshRunner{cfg: c} }

func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
		}
	}
	return p
}

// tofuCallback wraps a knownhosts DB with accept-new semantics: known host +
// matching key -> ok; known host + different key -> fail loud (MITM);
// unknown host -> accept and record for the next run.
func tofuCallback(knownPath string) (ssh.HostKeyCallback, error) {
	if err := os.MkdirAll(filepath.Dir(knownPath), 0o700); err != nil {
		return nil, err
	}
	var db ssh.HostKeyCallback
	if _, err := os.Stat(knownPath); err == nil {
		if db, err = knownhosts.New(knownPath); err != nil {
			return nil, err
		}
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if db != nil {
			err := db(hostname, remote, key)
			if err == nil {
				return nil
			}
			var kerr *knownhosts.KeyError
			if !errors.As(err, &kerr) || len(kerr.Want) != 0 {
				// changed key or malformed known_hosts — refuse
				return fmt.Errorf("host key mismatch for %s (возможен MITM; проверь %s): %w",
					hostname, knownPath, err)
			}
		}
		// unknown host: TOFU — append "[host]:port algo base64" and proceed.
		// NB: ssh.Dial passes the FULL addr string as hostname ("host:port"),
		// so build the known_hosts entry from the remote address, not hostname.
		host, portStr, _ := net.SplitHostPort(remote.String())
		entry := host
		if portStr != "" && portStr != "22" {
			entry = "[" + host + "]:" + portStr
		}
		line := entry + " " + key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
		if data, err := os.ReadFile(knownPath); err == nil && strings.Contains(string(data), line) {
			return nil // already recorded (e.g. racing writers) — nothing to do
		}
		f, err := os.OpenFile(knownPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("не могу записать known_hosts: %w", err)
		}
		defer f.Close()
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
		fmt.Printf("ssh: host key %s принят (TOFU) и записан в %s\n", fingerprint(key), knownPath)
		return nil
	}, nil
}

func fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func (s *sshRunner) connect() error {
	keyPath := expandTilde(s.cfg.SSHKey)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("ssh key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("ssh key %s: %w", keyPath, err)
	}
	knownPath := expandTilde("~/.ssh/known_hosts")
	hk, err := tofuCallback(knownPath)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.SSHPort)
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            s.cfg.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hk,
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("ssh %s@%s: %w (Entware поднялся? порт верный?)", s.cfg.SSHUser, addr, err)
	}
	s.client = client
	return nil
}

// run executes a shell script and returns combined output; a dropped
// connection is re-established once before giving up.
func (s *sshRunner) run(script string) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if s.client == nil {
			if err := s.connect(); err != nil {
				return "", err
			}
		}
		sess, err := s.client.NewSession()
		if err != nil {
			s.client = nil // stale connection — reconnect and retry once
			continue
		}
		defer sess.Close()
		var buf bytes.Buffer
		sess.Stdout, sess.Stderr = &buf, &buf
		err = sess.Run(script)
		return buf.String(), err
	}
	return "", errors.New("ssh session failed twice")
}

// upload streams data to remoteCmd's stdin (the `cat > file` pattern).
func (s *sshRunner) upload(data []byte, remoteCmd string) error {
	if s.client == nil {
		if err := s.connect(); err != nil {
			return err
		}
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	if err := sess.Start(remoteCmd); err != nil {
		return err
	}
	if _, err := stdin.Write(data); err != nil {
		stdin.Close()
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	return sess.Wait()
}
