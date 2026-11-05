// Package deploy pushes kgate and the VPN stack to the router over ssh.
package deploy

import (
	_ "embed"
	"fmt"
	"os"

	"kgate/internal/certs"
	"kgate/internal/model"
)

//go:embed payload.embed.tgz
var Payload []byte

// payloadIsPlaceholder reports the embedded 45-byte stub committed for fresh
// checkouts: deploying it would unpack nothing and wipe nothing, but the
// stack would be left broken — refuse loudly instead.
func payloadIsPlaceholder() bool { return len(Payload) < 1<<20 }

type Runner struct {
	c        *model.Config
	dry      bool
	ssh      *sshRunner
	SSH      func(script string) string
	Upld     func(data []byte, remoteCmd string) error
	Failures func() int
}

func New(c *model.Config, dry bool) *Runner {
	r := &Runner{c: c, dry: dry, ssh: newSSHRunner(c)}
	failures := 0
	r.SSH = func(script string) string {
		if dry {
			fmt.Println("DRY ssh:", script)
			return ""
		}
		out, err := r.ssh.run(script)
		if err != nil {
			failures++
			fmt.Printf("STAGE ERROR (%d): %v\n%s\n", failures, err, out)
		}
		return out
	}
	r.Failures = func() int { return failures }
	r.Upld = func(data []byte, remoteCmd string) error {
		if dry {
			fmt.Println("DRY upload", len(data), "bytes ->", remoteCmd)
			return nil
		}
		return r.ssh.upload(data, remoteCmd)
	}
	return r
}

// DestroyPlan renders what Destroy will do — printed for confirmation.
func DestroyPlan(c *model.Config) string {
	return fmt.Sprintf(`Действия на роутере %s:
  - остановить S99kgate (Proxy0 опустится — дом пойдёт напрямую)
  - opkg remove kgate, если стек ставился пакетом (снимет и sing-box)
  - удалить файлы: /opt/sbin/{kgate,sing-box}, /opt/etc/{kgate,sing-box},
    init-скрипт, ndm-commands.sh, логи
  - ndm: Proxy0 down, снять route-pin'ы (%s, 77.88.8.8) и name-server 77.88.8.8
Останется: sshd и Entware; политики-сценарии и Proxy0 в веб-интерфейсе;
клиентские файлы на ноутбуке (~/.kgate, ~/.local/bin/kgate).`, c.Host, c.ServerIP)
}

func (r *Runner) Files() {
	if payloadIsPlaceholder() {
		fmt.Println("FAIL: встроенный payload — заглушка (45B). Реальный стек не распространяется внутри релизного бинаря:")
		fmt.Println("      собери его локально из каталога репо: make payload (возьмёт local/etc или examples/etc), затем повтори kgate deploy")
		os.Exit(1)
	}
	fmt.Println("=== files: payload (kgate arm64 + sing-box + конфиги) ===")
	if err := r.Upld(Payload, `cat > /tmp/payload.tgz`); err != nil {
		fmt.Println("FAIL upload:", err)
		os.Exit(1)
	}
	fmt.Print(r.SSH(`mkdir -p /tmp/px && cd /tmp/px && rm -rf * && tar -xzf /tmp/payload.tgz
mv -f kgate-arm64 /opt/sbin/kgate
mv -f sing-box /opt/sbin/sing-box
mv -f ndm-commands.sh /opt/etc/ndm-commands.sh
mv -f S99kgate /opt/etc/init.d/S99kgate
mkdir -p /opt/etc/sing-box/rulesets
cp -f root/opt/etc/sing-box/config.json /opt/etc/sing-box/config.json
cp -f root/opt/etc/sing-box/rulesets/*.srs /opt/etc/sing-box/rulesets/ 2>/dev/null
cp -f root/opt/etc/ssh/authorized_keys /opt/etc/ssh/authorized_keys
grep -q "^sshd:" /opt/etc/passwd || cat root/opt/etc/passwd >> /opt/etc/passwd
chmod +x /opt/sbin/kgate /opt/sbin/sing-box /opt/etc/init.d/S99kgate
rm -rf /tmp/px /tmp/payload.tgz
mkdir -p /opt/etc/kgate /opt/etc/ssh /opt/var/log /opt/var/run
/opt/sbin/kgate version | head -1
opkg update >/dev/null 2>&1; for p in iptables openssh-server ca-bundle; do opkg list-installed | grep -q "^$p " || opkg install $p; done
opkg list-installed | grep -E "^(iptables|openssh-server) " | head -2`))
}

func (r *Runner) Migrate() {
	fmt.Println("=== migrate: legacy-обвязка -> демон ===")
	// 0) retire a previous routerctl install (if any); the kgate daemon takes over the stack
	fmt.Print(r.SSH(`[ -f /opt/etc/init.d/S99routerctl ] && { /opt/etc/init.d/S99routerctl stop 2>/dev/null; mv /opt/etc/init.d/S99routerctl /opt/etc/init.d/S99routerctl.disabled; }
rm -f /opt/var/run/routerctl*.pid /opt/var/run/routerctl.pid
true`))
	fmt.Print(r.SSH(`
# 1) старый S99sing-box под замок (иначе задвоит sing-box с демоном)
[ -f /opt/etc/init.d/S99sing-box ] && mv /opt/etc/init.d/S99sing-box /opt/etc/init.d/S99sing-box.disabled
# 2) удалить legacy-строки из rc.unslung (watchdog/apply/boot-autoup теперь внутри демона)
grep -vE "(rc-redirect|boot-autoup|\{kgate\})" /opt/etc/init.d/rc.unslung > /tmp/rcu && cat /tmp/rcu > /opt/etc/init.d/rc.unslung && rm /tmp/rcu
# 3) убить старый watchdog и его инстансы
for P in $(ps w | grep rc-redirect-watchdog | grep -v grep | awk "{print \$1}"); do kill $P 2>/dev/null; done
# 4) xray больше не нужен (заменил relay в kgate)
[ -f /opt/etc/init.d/S24xray ] && mv /opt/etc/init.d/S24xray /opt/etc/init.d/S24xray.disabled
killall xray 2>/dev/null
echo "legacy disabled"`))
}

func (r *Runner) ConfigAndCerts(cfg *model.Config) {
	fmt.Println("=== config + mTLS certs ===")
	yml, _ := yamlMarshal(cfg)
	if err := r.Upld(yml, `mkdir -p /opt/etc/kgate && cat > /opt/etc/kgate/kgate.yaml`); err != nil {
		fmt.Println("FAIL config upload:", err)
		os.Exit(1)
	}
	created, err := certs.Ensure(homeDir()+"/.kgate", cfg.Host)
	if err != nil {
		fmt.Println("FAIL certs:", err)
		os.Exit(1)
	}
	fmt.Println("certs:", map[bool]string{true: "сгенерированы новые", false: "переиспользованы существующие"}[created])
	home := homeDir()
	for _, pair := range [][2]string{
		{home + "/.kgate/ca.crt", "/opt/etc/kgate/ca.crt"},
		{home + "/.kgate/server.crt", "/opt/etc/kgate/server.crt"},
		{home + "/.kgate/server.key", "/opt/etc/kgate/server.key"},
	} {
		b, err := os.ReadFile(pair[0])
		if err != nil {
			fmt.Println("FAIL read", pair[0], err)
			os.Exit(1)
		}
		if err := r.Upld(b, `cat > `+pair[1]); err != nil {
			fmt.Println("FAIL cert upload:", err)
			os.Exit(1)
		}
	}
	fmt.Print(r.SSH(`chmod 600 /opt/etc/kgate/server.key`))
}

func (r *Runner) NDM() {
	fmt.Println("=== ndm: Proxy0, pins, DNS, политики ===")
	fmt.Print(r.SSH(`KGATE_SERVER_IP="` + r.c.ServerIP + `" sh /opt/etc/ndm-commands.sh 2>&1 || echo "ndm-commands.sh missing - run kgate files first"`))
}

func (r *Runner) Services() {
	fmt.Println("=== services: S99kgate start (демон берёт стек) ===")
	fmt.Print(r.SSH(`/opt/etc/init.d/S99kgate stop >/dev/null 2>&1; /opt/etc/init.d/S99kgate start; sleep 4; /opt/etc/init.d/S99kgate status`))
}

func (r *Runner) Preflight() {
	fmt.Println("=== preflight ===")
	fmt.Print(r.SSH(`test -d /opt/etc/init.d || { echo "Entware NOT mounted"; exit 1; }; cat /proc/uptime | awk "{print \"uptime: \" \$1 \"s\"}"`))
}

// Destroy undoes the deploy (the mechanical part — confirmation happens in
// main.go): stop the service, remove the stack files, clean the ndm pins.
func (r *Runner) Destroy() {
	fmt.Println("=== destroy: остановка и файлы ===")
	fmt.Print(r.SSH(`/opt/etc/init.d/S99kgate stop 2>/dev/null
if opkg list-installed | grep -q "^kgate "; then opkg remove kgate; fi
rm -f  /opt/etc/init.d/S99kgate /opt/etc/init.d/S99kgate.disabled
rm -rf /opt/etc/kgate /opt/etc/sing-box
rm -f  /opt/etc/ndm-commands.sh /opt/sbin/kgate /opt/sbin/sing-box
rm -rf /opt/var/log/kgate*.log /opt/var/log/singbox.log
killall kgate sing-box 2>/dev/null
echo "стек удалён"`))
	fmt.Println("=== destroy: ndm (туннель + пины) ===")
	ndm := `ndmc -c "interface Proxy0 down"`
	if r.c.ServerIP != "" {
		ndm += `
ndmc -c "no ip route ` + r.c.ServerIP + ` ISP"`
	}
	ndm += `
ndmc -c "no ip route 77.88.8.8 ISP"
ndmc -c "no ip name-server 77.88.8.8"
echo "ndm очищен"`
	fmt.Print(r.SSH(ndm))
	fmt.Println("готово. Политики-сценарии (VPN-TV и др.) и подключение Proxy0 в веб-интерфейсе удалите руками, если нужны.")
}
