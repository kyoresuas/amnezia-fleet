// fleet-probe, проверка доступности адресов из РФ
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/probe"
)

type config struct {
	server      string
	token       string
	key         awg.Key
	timeout     time.Duration
	concurrency int
}

// loadConfig читает переменные окружения
func loadConfig() (config, error) {
	c := config{
		server:      strings.TrimRight(os.Getenv("FLEET_SERVER_URL"), "/"),
		token:       os.Getenv("FLEET_PROBE_TOKEN"),
		timeout:     8 * time.Second,
		concurrency: 8,
	}
	if v, err := time.ParseDuration(os.Getenv("FLEET_PROBE_TIMEOUT")); err == nil && v > 0 {
		c.timeout = v
	}
	if v, err := strconv.Atoi(os.Getenv("FLEET_PROBE_CONCURRENCY")); err == nil && v > 0 {
		c.concurrency = v
	}
	var errs []error
	if c.server == "" || c.token == "" {
		errs = append(errs, errors.New("нужны FLEET_SERVER_URL и FLEET_PROBE_TOKEN"))
	}
	key, err := awg.ParseKey(os.Getenv("FLEET_PROBE_PRIVATE_KEY"))
	if err != nil {
		errs = append(errs, fmt.Errorf("FLEET_PROBE_PRIVATE_KEY: %w", err))
	}
	c.key = key
	return c, errors.Join(errs...)
}

// main запускает цикл проверок до SIGINT или SIGTERM
func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := loadConfig()
	if err != nil {
		log.Error("конфигурация", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	prober := probe.New(cfg.key, cfg.timeout, cfg.concurrency, log)
	client := &http.Client{Timeout: 30 * time.Second}
	interval := 30 * time.Second
	log.Info("fleet-probe запущен", "server", cfg.server)
	for ctx.Err() == nil {
		targets, err := fetchTargets(ctx, client, cfg)
		if err != nil {
			log.Warn("получение целей", "err", err)
		} else {
			if targets.IntervalSeconds > 0 {
				interval = time.Duration(targets.IntervalSeconds) * time.Second
			}
			results := prober.CheckAll(ctx, targets.Targets)
			failed := 0
			for _, r := range results {
				if !r.OK {
					failed++
				}
			}
			log.Info("проверка завершена", "targets", len(results), "failed", failed)
			if err := sendResults(ctx, client, cfg, results); err != nil {
				log.Warn("отправка результатов", "err", err)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}

// fetchTargets запрашивает список адресов для проверки
func fetchTargets(ctx context.Context, c *http.Client, cfg config) (agentapi.ProbeTargets, error) {
	var out agentapi.ProbeTargets
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.server+agentapi.PathProbeTargets, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	resp, err := c.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return out, fmt.Errorf("%d %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// sendResults отправляет результаты проверок
func sendResults(ctx context.Context, c *http.Client, cfg config, results []agentapi.ProbeResult) error {
	raw, err := json.Marshal(agentapi.ProbeResults{Results: results})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.server+agentapi.PathProbeResults, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%d %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}
