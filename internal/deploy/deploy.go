// Package deploy pushes kgate and the VPN stack to the router over ssh.
// Every stage reports itself to the console with a colored ✓/✗ mark and
// duration (plain text when stdout is not a terminal or NO_COLOR is set).
package deploy

import (
	"path/filepath"

	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"kgate/internal/certs"
	"kgate/internal/model"
)

// Payload объявлен в deploy_stub.go (по умолчанию: 45B заглушка) и
// deploy_real.go (-tags kgate_real_payload: реальный payload из payload.tgz).

// payloadIsPlaceholder reports the embedded 45-byte stub committed for fresh
// checkouts: deploying it would unpack nothing and wipe nothing, but the
// stack would be left broken — refuse loudly instead.
func payloadIsPlaceholder() bool { return len(Payload) < 1<<20 }

type Runner struct {
	c        *model.Config
	dry      bool
	color    bool
	ssh      *sshRunner
	failures int
}

func New(c *model.Config, dry bool) *Runner {
	return &Runner{c: c, dry: dry, color: useColor(), ssh: newSSHRunner(c)}
}

// Failures returns the number of failed steps so far.
func (r *Runner) Failures() int { return r.failures }

// ---- console UX ----

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (r *Runner) mark(ok bool) string {
	if !r.color {
		if ok {
			return "[OK]"
		}
		return "[FAIL]"
	}
	if ok {
		return "\033[32m✓\033[0m"
	}
	return "\033[31m✗\033[0m"
}

// step runs a named script, printing a colored ✓/✗ line with duration; on
// failure the script output is indented under the mark and failures counter
// grows.
func (r *Runner) step(name, script string) string {
	if r.dry {
		fmt.Printf("  %s %s (dry-run, скрипт пропущен)\n", r.mark(true), name)
		return ""
	}
	t0 := time.Now()
	out, err := r.ssh.run(script)
	d := time.Since(t0).Round(100 * time.Millisecond)
	if err != nil {
		r.failures++
		fmt.Printf("  %s %s (%v)\n", r.mark(false), name, d)
	} else {
		fmt.Printf("  %s %s (%v)\n", r.mark(true), name, d)
	}
	// вывод скрипта виден и на успехе (с отступом): version-evidence,
	// S99 status — зелёная галочка должна быть объяснима из консоли
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line != "" {
			fmt.Println("      " + line)
		}
	}
	return out
}

// upload transfers data with the same step reporting; fatal failures abort.
func (r *Runner) upload(data []byte, remoteCmd, name string) {
	if r.dry {
		fmt.Printf("  %s %s (dry-run, %d байт не передаются)\n", r.mark(true), name, len(data))
		return
	}
	t0 := time.Now()
	err := r.ssh.upload(data, remoteCmd)
	d := time.Since(t0).Round(100 * time.Millisecond)
	if err != nil {
		r.failures++
		fmt.Printf("  %s %s (%v): %v\n", r.mark(false), name, d, err)
		return
	}
	fmt.Printf("  %s %s — %d байт (%v)\n", r.mark(true), name, len(data), d)
}

// fatal prints a red abort line and exits — used for pre-flight blockers
// where continuing would leave the router half-configured.
func (r *Runner) fatal(msg string) {
	fmt.Printf("  %s %s\n", r.mark(false), msg)
	os.Exit(1)
}

// DestroyPlan renders what Destroy will do — printed for confirmation.
func DestroyPlan(c *model.Config) string {
	pins := c.ServerIP
	if pins == "" {
		pins = "—"
	}
	return fmt.Sprintf(`Действия на роутере %s:
  - остановить S99kgate (Proxy0 опустится — дом пойдёт напрямую)
  - opkg remove kgate, если стек ставился пакетом (снимет и sing-box)
  - удалить файлы: /opt/sbin/{kgate,sing-box}, /opt/etc/{kgate,sing-box},
    init-скрипт, ndm-commands.sh, логи
  - ndm: снять route-pin'ы (%s, 77.88.8.8) и name-server 77.88.8.8
  - ndm: ПОЛНОСТЬЮ удалить интерфейс Proxy0 и политики-сценарии
    (VPN-TV, VPN-Laptops-Phones, DIRECT-NOVPN)
  - проверить, что следов kgate в running-config не осталось
Останется: sshd и Entware; клиентские файлы на ноутбуке
(~/.kgate, ~/.local/bin/kgate).`, c.Host, pins)
}

// ---- deploy stages ----

func (r *Runner) Preflight() {
	fmt.Println("→ preflight")
	r.step("Entware на месте, uptime", `test -d /opt/etc/init.d || { echo "Entware NOT mounted"; exit 1; }; cat /proc/uptime | awk "{print \"uptime: \" \$1 \"s\"}"`)
}

func (r *Runner) Files() {
	if payloadIsPlaceholder() && !r.dry {
		fmt.Println("→ deploy: files")
		r.fatal("встроенный payload — заглушка; релизный бинарь не несёт стек. Собери локально: make payload, затем повтори kgate deploy")
	}
	fmt.Println("→ deploy: files")
	r.upload(Payload, `cat > /tmp/payload.tgz`, "передача payload на роутер")
	r.step("распаковка и раскладка (бинари, S99, ndm, конфиг, rulesets)", `mkdir -p /tmp/px && cd /tmp/px && rm -rf * && tar -xzf /tmp/payload.tgz
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
/opt/sbin/kgate version | head -1`)
	r.step("opkg-зависимости (iptables, openssh-server)", `opkg update >/dev/null 2>&1; for p in iptables openssh-server; do opkg list-installed | grep -q "^$p " || opkg install $p; done; opkg list-installed | grep -E "^(iptables|openssh-server) " | head -2`)
}

func (r *Runner) Migrate() {
	fmt.Println("→ deploy: migrate (legacy под замок)")
	// retire a previous routerctl install (if any); the kgate daemon takes over the stack
	r.step("retire S99routerctl, глушение S99sing-box/S24xray, чистка rc.unslung", `[ -f /opt/etc/init.d/S99routerctl ] && { /opt/etc/init.d/S99routerctl stop 2>/dev/null; mv /opt/etc/init.d/S99routerctl /opt/etc/init.d/S99routerctl.disabled; }
rm -f /opt/var/run/routerctl*.pid /opt/var/run/routerctl.pid
[ -f /opt/etc/init.d/S99sing-box ] && mv /opt/etc/init.d/S99sing-box /opt/etc/init.d/S99sing-box.disabled
grep -vE "(rc-redirect|boot-autoup|\{kgate\})" /opt/etc/init.d/rc.unslung > /tmp/rcu && cat /tmp/rcu > /opt/etc/init.d/rc.unslung && rm /tmp/rcu
for P in $(ps w | grep rc-redirect-watchdog | grep -v grep | awk "{print \$1}"); do kill $P 2>/dev/null; done
[ -f /opt/etc/init.d/S24xray ] && mv /opt/etc/init.d/S24xray /opt/etc/init.d/S24xray.disabled
killall xray 2>/dev/null
echo "legacy disabled"`)
}

func (r *Runner) ConfigAndCerts(cfg *model.Config) {
	fmt.Println("→ deploy: config + mTLS certs")
	yml, _ := yamlMarshal(cfg)
	r.upload(yml, `mkdir -p /opt/etc/kgate && cat > /opt/etc/kgate/kgate.yaml`, "рендер kgate.yaml на роутер")
	if r.dry {
		fmt.Printf("  %s mTLS-сертификаты (dry-run: генерация и чтение пропущены)\n", r.mark(true))
		return
	}
	// каталог сертов = каталог api.ca из конфига (уже развёрнут expandHomes;
	// имена файлов фиксированы генерацией certs.Ensure)
	certDir := filepath.Dir(cfg.API.CA)
	created, err := certs.Ensure(certDir, cfg.Host)
	if err != nil {
		r.fatal("генерация mTLS-сертификатов: " + err.Error())
	}
	fmt.Printf("  %s mTLS-сертификаты: %s\n", r.mark(true), map[bool]string{true: "сгенерированы новые (ECDSA P-256)", false: "переиспользованы существующие"}[created])
	home := certDir
	for _, pair := range [][2]string{
		{home + "/ca.crt", "/opt/etc/kgate/ca.crt"},
		{home + "/server.crt", "/opt/etc/kgate/server.crt"},
		{home + "/server.key", "/opt/etc/kgate/server.key"},
	} {
		b, err := os.ReadFile(pair[0])
		if err != nil {
			r.fatal("чтение " + pair[0] + ": " + err.Error())
		}
		r.upload(b, `cat > `+pair[1], "загрузка "+pair[1])
	}
	r.step("chmod 600 server.key", `chmod 600 /opt/etc/kgate/server.key`)
}

func (r *Runner) NDM() {
	fmt.Println("→ deploy: ndm (Proxy0, пины, DNS, политики)")
	r.step("ndm-commands.sh идемпотентным прогоном", `{ test -f /opt/etc/ndm-commands.sh || { echo "ndm-commands.sh missing — run kgate files first"; exit 1; }; KGATE_SERVER_IP="`+r.c.ServerIP+`" sh /opt/etc/ndm-commands.sh 2>&1; }`)
}

func (r *Runner) Services() {
	fmt.Println("→ deploy: services")
	// stop+start, не restart: у S99, развёрнутого старыми версиями kgate,
	// restart-кейса нет — --only services обязан работать с любой генерацией скрипта
	r.step("S99kgate stop+start + статус демона", `/opt/etc/init.d/S99kgate stop >/dev/null 2>&1; sleep 1; /opt/etc/init.d/S99kgate start; sleep 4; /opt/etc/init.d/S99kgate status`)
}

// ---- destroy ----

// Destroy undoes the deploy (the mechanical part — confirmation happens in
// main.go): stop the service, remove the stack files, delete the ndm objects
// (Proxy0 interface AND scenario policies — no rudiments left behind) and
// verify the running-config is clean.
func (r *Runner) Destroy() {
	fmt.Println("→ destroy: остановка и пакет")
	r.step("S99kgate stop (Proxy0 down) + opkg remove kgate", `/opt/etc/init.d/S99kgate stop 2>/dev/null
if opkg list-installed | grep -q "^kgate "; then opkg remove kgate; fi
killall kgate sing-box 2>/dev/null
echo "stack stopped"`)

	fmt.Println("→ destroy: файлы стека")
	r.step("удаление бинарей, init-скрипта, конфигов и логов", `rm -f  /opt/etc/init.d/S99kgate /opt/etc/init.d/S99kgate.disabled
rm -rf /opt/etc/kgate /opt/etc/sing-box
rm -f  /opt/etc/ndm-commands.sh /opt/sbin/kgate /opt/sbin/sing-box
rm -rf /opt/var/log/kgate*.log /opt/var/log/singbox.log
echo "stack files removed"`)

	fmt.Println("→ destroy: ndm (пины, DNS)")
	pins := ""
	if r.c.ServerIP != "" {
		pins += `
ndmc -c "no ip route ` + r.c.ServerIP + ` ISP"`
	}
	pins += `
ndmc -c "no ip route 77.88.8.8 ISP"
ndmc -c "no ip name-server 77.88.8.8"
echo "pins removed"`
	r.step("снятие route-pin'ов и name-server", pins)

	fmt.Println("→ destroy: ndm (объекты)")
	r.step("удаление интерфейса Proxy0 и политик-сценариев", `ndmc -c "no ip policy VPN-TV"
ndmc -c "no ip policy VPN-Laptops-Phones"
ndmc -c "no ip policy DIRECT-NOVPN"
ndmc -c "no interface Proxy0"
echo "ndm objects removed"`)

	fmt.Println("→ destroy: контроль чистоты")
	// скрипт сам валидирует счётчик (test -eq 0): при остатках step поставит ✗
	// и напечатает leftover=N с отступом
	r.step("следы kgate в running-config (ожидаем 0)", `command -v ndmc >/dev/null || { echo "ndmc not found"; exit 1; }
LEFT=$(ndmc -c "show running-config" 2>/dev/null | grep -cE "Proxy0|VPN-TV|VPN-Laptops-Phones|DIRECT-NOVPN" || true)
echo "leftover=$LEFT"
test "$LEFT" -eq 0`)
	fmt.Println("готово. На ноутбуке остались клиентские файлы (~/.kgate, ~/.local/bin/kgate) — удали руками, если больше не нужен клиент.")
}
