package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"kgate/internal/certs"
	"kgate/internal/client"
	"kgate/internal/daemon"
	"kgate/internal/deploy"
	"kgate/internal/model"
	"kgate/internal/update"

	"github.com/spf13/cobra"
)

var appVersion = "dev"
var cfgPath string
var onlyStage string
var dryRun bool
var assumeYes bool

// configTemplate is the packaged yaml template with placeholders; `kgate
// config create` copies it to the default path and opens the editor.
//
//go:embed examples/kgate.yaml.example
var configTemplate []byte

// manPage is the kgate(1) roff source; `kgate man` renders it through man(1)
// when available.
//
//go:embed docs/kgate.1
var manPage []byte

// templateMarkers stay from the untouched template: if they survive the edit,
// the config is not filled in yet and we say so loudly.
var templateMarkers = []string{"203.0.113.10"}

// stdinIsTTY reports whether stdin is an interactive terminal (destroy
// confirmation requires one unless --yes is passed).
func stdinIsTTY() bool {
	st, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func stdoutIsTTY() bool {
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func load() *model.Config {
	c, err := model.Load(cfgPath)
	if err != nil {
		fmt.Println("FAIL config:", err)
		os.Exit(1)
	}
	return c
}

// defaultCfgPath resolves the default config location: $KGATE_CONFIG, then
// ~/.kgate/kgate.yaml (canonical), falling back to ./kgate.yaml for a
// repo-local checkout that predates the canonical path.
func defaultCfgPath() string {
	if p := os.Getenv("KGATE_CONFIG"); p != "" {
		return p
	}
	p := canonicalCfgPath()
	if _, err := os.Stat(p); err != nil {
		if _, err := os.Stat("kgate.yaml"); err == nil {
			return "kgate.yaml"
		}
	}
	return p
}

// canonicalCfgPath is the canonical location WITHOUT the CWD fallback —
// `config create` targets it so a fresh setup never lands in the CWD.
func canonicalCfgPath() string {
	if p := os.Getenv("KGATE_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".kgate", "kgate.yaml")
}

// runEditor opens path in $VISUAL/$EDITOR (vi as last resort) and waits.
func runEditor(path string) error {
	editor := firstNonEmpty(os.Getenv("VISUAL"), os.Getenv("EDITOR"), "vi")
	cmd := exec.Command(editor, path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("редактор %q: %v — отредактируй файл вручную: %s", editor, err, path)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// configCmd is the `kgate config` group: create/view/path/edit.
func configCmd() *cobra.Command {
	cfg := &cobra.Command{
		Use:   "config",
		Short: "работа с yaml-конфигом (create/view/path/edit)",
		Long: `Конфиг по дефолтному пути: ~/.kgate/kgate.yaml (переопределяется -c и $KGATE_CONFIG).

  kgate config create — создать конфиг из встроенного шаблона и открыть редактор
  kgate config view   — показать текущий конфиг
  kgate config path   — напечатать путь к конфигу
  kgate config edit   — открыть конфиг в редакторе`,
	}
	create := &cobra.Command{
		Use:   "create",
		Short: "создать конфиг из шаблона по дефолтному пути и открыть редактор",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("config") {
				cfgPath = canonicalCfgPath() // fresh setups target the canonical path, never the CWD
			}
			if cfgPath == "" {
				cfgPath = defaultCfgPath()
			}
			if _, err := os.Stat(cfgPath); err == nil {
				return fmt.Errorf("конфиг уже существует: %s — правь через `kgate config edit`", cfgPath)
			}
			if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(cfgPath, configTemplate, 0o600); err != nil {
				return err
			}
			fmt.Println("создан:", cfgPath)
			if err := runEditor(cfgPath); err != nil {
				fmt.Println("WARN:", err)
			}
			b, _ := os.ReadFile(cfgPath)
			var stale []string
			for _, m := range templateMarkers {
				if strings.Contains(string(b), m) {
					stale = append(stale, m)
				}
			}
			if len(stale) > 0 {
				fmt.Printf("ВНИМАНИЕ: в конфиге остались шаблонные значения (%s) — замени их реальными\n",
					strings.Join(stale, ", "))
			}
			fmt.Printf("конфиг готов: %s\nдальше: kgate deploy\n", cfgPath)
			return nil
		},
	}
	view := &cobra.Command{
		Use:   "view",
		Short: "показать содержимое конфига",
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := os.ReadFile(cfgPath)
			if err != nil {
				return fmt.Errorf("конфига нет (%s) — создай: kgate config create", cfgPath)
			}
			fmt.Println(string(b))
			return nil
		},
	}
	path := &cobra.Command{
		Use:   "path",
		Short: "напечатать путь к конфигу",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(cfgPath)
		},
	}
	edit := &cobra.Command{
		Use:   "edit",
		Short: "открыть конфиг в редакторе ($VISUAL/$EDITOR)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(cfgPath); err != nil {
				return fmt.Errorf("конфига нет (%s) — создай: kgate config create", cfgPath)
			}
			return runEditor(cfgPath)
		},
	}
	for _, c := range []*cobra.Command{create, view, path, edit} {
		cfg.AddCommand(c)
	}
	return cfg
}

func main() {
	root := &cobra.Command{
		Use:   "kgate",
		Short: "kgate — одна утилита: демон-супервизор на роутере + mTLS-клиент + деплойер",
		Long: `kgate — единая утилита управления VPN-стеком Netcraze Ultra.

Роли:
  serve    — демон на роутере: супервизор sing-box, DNS-перехват (iptables),
             авто-подъём туннеля, mTLS API
  deploy   — деплой стека на роутер по ssh (payload встроен; алиас: apply)
  destroy  — снять стек с роутера (с подтверждением; --yes для скриптов)
  config   — create/view/path/edit: yaml-конфиг по дефолтному пути
  update   — самобновление бинарника из GitHub Releases
  man      — man-страница kgate(1)
  status/verify/toggle/ruexit/logs/reboot — mTLS-клиент с ноутбука`,
		SilenceUsage: true,
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", defaultCfgPath(), "yaml-конфиг (или $KGATE_CONFIG)")

	root.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "демон на роутере (супервизор + API)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.New(load()).Run()
		},
	})

	deployCmd := &cobra.Command{
		Use:     "deploy",
		Aliases: []string{"apply"},
		Short:   "деплой стека на роутер по ssh (с нуля до рабочего состояния)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := load()
			r := deploy.New(c, dryRun)
			r.Preflight()
			only := func(s string) bool { return onlyStage == "all" || onlyStage == s }
			if only("files") {
				r.Files()
			}
			if only("files") { // legacy migration is part of the files stage
				r.Migrate()
			}
			if only("config") {
				r.ConfigAndCerts(c)
			}
			if only("ndm") {
				r.NDM()
			}
			if only("services") {
				r.Services()
			}
			if r.Failures() > 0 {
				fmt.Printf("deploy завершён С ОШИБКАМИ (%d стадий/шагов) — см. лог выше\n", r.Failures())
				os.Exit(1)
			}
			if !dryRun && onlyStage == "all" {
				fmt.Println("=== ждём демона и верифицируем ===")
				time.Sleep(5 * time.Second)
				client.Status(c)
				client.Verify(c)
			}
			return nil
		},
	}
	deployCmd.Flags().StringVar(&onlyStage, "only", "all", "all|files|config|ndm|services")
	deployCmd.Flags().BoolVar(&dryRun, "dry-run", false, "показать план без изменений")
	root.AddCommand(deployCmd)

	destroy := &cobra.Command{
		Use:     "destroy",
		Aliases: []string{"undeploy"},
		Short:   "снять стек с роутера (обратный deploy; подтверждение обязательно)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := load()
			r := deploy.New(c, dryRun)
			r.Preflight()
			if dryRun {
				fmt.Println("DRY-RUN — план destroy (изменений не будет):")
			} else {
				fmt.Println(deploy.DestroyPlan(c))
				if !assumeYes {
					if !stdinIsTTY() {
						return fmt.Errorf("stdin — не терминал: подтверждение невозможно; для скриптов добавь --yes")
					}
					fmt.Print("\nСнять стек kgate с роутера? Введи y для продолжения: ")
					answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
					answer = strings.ToLower(strings.TrimSpace(answer))
					if answer != "y" && answer != "yes" && answer != "д" && answer != "да" {
						fmt.Println("отменено — ничего не изменено")
						return nil
					}
				}
			}
			r.Destroy()
			if r.Failures() > 0 {
				fmt.Printf("destroy завершён С ОШИБКАМИ (%d шагов) — см. лог выше\n", r.Failures())
				os.Exit(1)
			}
			return nil
		},
	}
	destroy.Flags().BoolVar(&assumeYes, "yes", false, "не спрашивать подтверждение (для скриптов)")
	destroy.Flags().BoolVar(&dryRun, "dry-run", false, "показать план без изменений")
	root.AddCommand(destroy)

	manCmd := &cobra.Command{
		Use:   "man",
		Short: "man-страница kgate(1) (roff; в терминале рендерится через man)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if stdoutIsTTY() {
				if manBin, err := exec.LookPath("man"); err == nil {
					tmp := filepath.Join(os.TempDir(), "kgate.1")
					if err := os.WriteFile(tmp, manPage, 0o644); err == nil {
						defer os.Remove(tmp)
						viewer := exec.Command(manBin, "-l", tmp)
						viewer.Stdin, viewer.Stdout, viewer.Stderr = os.Stdin, os.Stdout, os.Stderr
						if err := viewer.Run(); err == nil {
							return nil
						}
					}
				}
			}
			os.Stdout.Write(manPage)
			if stdoutIsTTY() {
				fmt.Println("\n(hint: выше roff-исходник; man недоступен — `kgate man | man -l -` для рендера)")
			}
			return nil
		},
	}
	root.AddCommand(manCmd)

	root.AddCommand(configCmd())

	root.AddCommand(&cobra.Command{
		Use:   "update",
		Short: "самобновление: GitHub Releases → проверка версии → атомарная замена (+ рестарт сервиса на роутере)",
		RunE: func(cmd *cobra.Command, args []string) error {
			os.Exit(update.Run(appVersion))
			return nil
		},
	})

	certsCmd := &cobra.Command{
		Use:   "certs",
		Short: "генерация mTLS-сертификатов локально (обычно не нужна — deploy делает сам)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := load()
			created, err := certs.Ensure(homeOr(c.API.CA), c.Host)
			if err != nil {
				return err
			}
			fmt.Println("certs:", map[bool]string{true: "generated", false: "already exist"}[created])
			return nil
		},
	}
	root.AddCommand(certsCmd)

	root.AddCommand(&cobra.Command{Use: "status", Short: "статус стека через демона",
		RunE: func(cmd *cobra.Command, args []string) error { client.Status(load()); return nil }})
	root.AddCommand(&cobra.Command{Use: "verify", Short: "батарея проверок (демон + локальный socks-тест)",
		RunE: func(cmd *cobra.Command, args []string) error { client.Verify(load()); return nil }})
	toggle := &cobra.Command{Use: "toggle <on|off>", Args: cobra.ExactArgs(1),
		Short: "тумблер HYST VPN",
		RunE:  func(cmd *cobra.Command, args []string) error { client.Toggle(load(), args[0]); return nil }}
	root.AddCommand(toggle)
	ruexit := &cobra.Command{Use: "ruexit <on|off>", Args: cobra.ExactArgs(1),
		Short: "RU-анонимизация (global/rule; нужен серверный RU-rule)",
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := "rule"
			if args[0] == "on" {
				mode = "global"
			}
			client.Ruexit(load(), mode)
			return nil
		}}
	root.AddCommand(ruexit)
	root.AddCommand(&cobra.Command{Use: "logs", Short: "логи демона",
		RunE: func(cmd *cobra.Command, args []string) error { client.Logs(load()); return nil }})
	root.AddCommand(&cobra.Command{Use: "reboot", Short: "ребут роутера",
		RunE: func(cmd *cobra.Command, args []string) error { client.Reboot(load()); return nil }})

	ver := &cobra.Command{Use: "version", Short: "версия", Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("kgate %s (serve + mTLS client + deployer)\n", appVersion)
	}}
	root.AddCommand(ver)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func homeOr(_ string) string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/.kgate"
	}
	return h + "/.kgate"
}
