//go:build linux

// fleet-agent, агент узла
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kyoresuas/amnezia-fleet/internal/agent"
)

// main запускает агента и завершает его по SIGINT или SIGTERM
func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := agent.LoadConfig()
	if err != nil {
		log.Error("конфигурация", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("fleet-agent запущен", "version", agent.Version, "iface", cfg.Iface, "server", cfg.ServerURL)
	if err := agent.New(cfg, log).Run(ctx); err != nil {
		log.Error("агент остановлен с ошибкой", "err", err)
		os.Exit(1)
	}
}
