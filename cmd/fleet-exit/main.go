//go:build linux

// fleet-exit, выход для трафика выбранных доменов
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kyoresuas/amnezia-fleet/internal/exit"
)

// main запускает выход и завершает его по SIGINT или SIGTERM
func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := exit.LoadConfig()
	if err != nil {
		log.Error("конфигурация", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := exit.New(cfg, log).Run(ctx); err != nil {
		log.Error("выход остановлен с ошибкой", "err", err)
		os.Exit(1)
	}
}
