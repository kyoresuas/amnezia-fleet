// fleetd, control plane
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/controlplane"
	"github.com/kyoresuas/amnezia-fleet/internal/dnsprovider"
	"github.com/kyoresuas/amnezia-fleet/internal/secret"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
	"github.com/kyoresuas/amnezia-fleet/internal/telemetry"
)

// main запускает fleetd и завершает его по SIGINT или SIGTERM
func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fleetd остановлен с ошибкой", "err", err)
		os.Exit(1)
	}
}

// run собирает зависимости и запускает сервер
func run(log *slog.Logger) error {
	cfg, err := controlplane.LoadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	box, err := secret.NewBox(cfg.MasterKey)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL, box)
	if err != nil {
		return err
	}
	defer st.Close()

	var tele *telemetry.Repo
	if cfg.ClickHouseURL != "" {
		ch, err := telemetry.NewClickHouse(cfg.ClickHouseURL)
		if err != nil {
			return err
		}
		tele, err = telemetry.NewRepo(ctx, ch, telemetry.Retention{
			UsageDays: cfg.RetentionUsageDays, FlowsDays: cfg.RetentionFlowsDays, DNSDays: cfg.RetentionDNSDays,
		})
		if err != nil {
			return err
		}
	} else {
		log.Warn("FLEET_CLICKHOUSE_URL не задан: телеметрия и лимиты трафика отключены")
	}

	var dns dnsprovider.Provider = dnsprovider.Noop{Log: log}
	if cfg.DNSProvider == "cloudflare" {
		dns = dnsprovider.NewCloudflare(cfg.CloudflareToken, cfg.CloudflareZoneID)
	}

	srv := controlplane.NewServer(cfg, st, tele, dns, log)
	go srv.RunReconciler(ctx)
	go srv.RunLimits(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// с запасом под long-poll агентов
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("fleetd слушает", "addr", cfg.Listen)
		errCh <- httpSrv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}
