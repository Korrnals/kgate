package main

import (
	"time"
	"fmt"
	"os"

	"kgate/internal/certs"
	"kgate/internal/client"
	"kgate/internal/daemon"
	"kgate/internal/deploy"
	"kgate/internal/model"

	"github.com/spf13/cobra"
)

var appVersion = "dev"
var cfgPath string
var onlyStage string
var dryRun bool

func load() *model.Config {
	c, err := model.Load(cfgPath)
	if err != nil {
		fmt.Println("FAIL config:", err)
		os.Exit(1)
	}
	return c
}

func main() {
	root := &cobra.Command{
		Use:   "kgate",
		Short: "kgate — одна утилита: демон-супервизор на роутере + mTLS-клиент + деплойер",
		Long: `kgate — единая утилита управления VPN-стеком Netcraze Ultra.

Роли:
  serve    — демон на роутере: супервизор sing-box/xray, DNS-правила (ndm-флаши),
             авто-подъём туннеля, mTLS API для клиента
  apply    — деплойер: установка всего стека на роутер по ssh (payload встроен)
  status/verify/toggle/ruexit/logs/reboot — mTLS-клиент с ноутбука`,
		SilenceUsage: true,
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "kgate.yaml", "yaml-конфиг")

	root.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "демон на роутере (супервизор + API)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.New(load()).Run()
		},
	})

	apply := &cobra.Command{
		Use:   "apply",
		Short: "деплой стека на роутер по ssh (с нуля до рабочего состояния)",
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
			if !dryRun && onlyStage == "all" {
				fmt.Println("=== ждём демона и верифицируем ===")
				time.Sleep(5 * time.Second)
				client.Status(c)
				client.Verify(c)
			}
			return nil
		},
	}
	apply.Flags().StringVar(&onlyStage, "only", "all", "all|files|config|ndm|services")
	apply.Flags().BoolVar(&dryRun, "dry-run", false, "показать план без изменений")
	root.AddCommand(apply)

	certsCmd := &cobra.Command{
		Use:   "certs",
		Short: "генерация mTLS-сертификатов локально (обычно не нужна — apply делает сам)",
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
		RunE: func(cmd *cobra.Command, args []string) error { client.Toggle(load(), args[0]); return nil }}
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
