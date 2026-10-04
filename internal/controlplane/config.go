// Package controlplane
package controlplane

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Listen        string
	DatabaseURL   string
	ClickHouseURL string
	MasterKey     string
	AdminToken    string

	DistDir            string
	DNSProvider        string
	CloudflareToken    string
	CloudflareZoneID   string
	DNSReconcileEvery  time.Duration
	NodeStaleAfter     time.Duration
	ProbeInterval      time.Duration
	ProbeFailThreshold int
	AutoBlock          bool

	CollectFlows bool
	CollectDNS   bool

	RetentionUsageDays int
	RetentionFlowsDays int
	RetentionDNSDays   int

	LimitsCheckEvery time.Duration
}

// LoadConfig читает конфигурацию и проверяет обязательные поля
func LoadConfig() (Config, error) {
	c := Config{
		Listen:             env("FLEET_LISTEN", ":8080"),
		DatabaseURL:        os.Getenv("FLEET_DATABASE_URL"),
		ClickHouseURL:      os.Getenv("FLEET_CLICKHOUSE_URL"),
		MasterKey:          os.Getenv("FLEET_MASTER_KEY"),
		AdminToken:         os.Getenv("FLEET_ADMIN_TOKEN"),
		DistDir:            env("FLEET_DIST_DIR", "/usr/local/share/fleetd"),
		DNSProvider:        env("FLEET_DNS_PROVIDER", "none"),
		CloudflareToken:    os.Getenv("FLEET_CLOUDFLARE_API_TOKEN"),
		CloudflareZoneID:   os.Getenv("FLEET_CLOUDFLARE_ZONE_ID"),
		DNSReconcileEvery:  envDuration("FLEET_DNS_RECONCILE_EVERY", 15*time.Second),
		NodeStaleAfter:     envDuration("FLEET_NODE_STALE_AFTER", 90*time.Second),
		ProbeInterval:      envDuration("FLEET_PROBE_INTERVAL", 30*time.Second),
		ProbeFailThreshold: envInt("FLEET_PROBE_FAIL_THRESHOLD", 3),
		AutoBlock:          envBool("FLEET_AUTO_BLOCK", true),
		CollectFlows:       envBool("FLEET_COLLECT_FLOWS", true),
		CollectDNS:         envBool("FLEET_COLLECT_DNS", true),
		RetentionUsageDays: envInt("FLEET_RETENTION_USAGE_DAYS", 400),
		RetentionFlowsDays: envInt("FLEET_RETENTION_FLOWS_DAYS", 90),
		RetentionDNSDays:   envInt("FLEET_RETENTION_DNS_DAYS", 30),
		LimitsCheckEvery:   envDuration("FLEET_LIMITS_CHECK_EVERY", 5*time.Minute),
	}
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("FLEET_DATABASE_URL не задан"))
	}
	if c.MasterKey == "" {
		errs = append(errs, errors.New("FLEET_MASTER_KEY не задан (openssl rand -base64 32)"))
	}
	if len(c.AdminToken) < 32 {
		errs = append(errs, errors.New("FLEET_ADMIN_TOKEN должен быть не короче 32 символов"))
	}
	switch c.DNSProvider {
	case "none":
	case "cloudflare":
		if c.CloudflareToken == "" || c.CloudflareZoneID == "" {
			errs = append(errs, errors.New("для cloudflare нужны FLEET_CLOUDFLARE_API_TOKEN и FLEET_CLOUDFLARE_ZONE_ID"))
		}
	default:
		errs = append(errs, fmt.Errorf("неизвестный FLEET_DNS_PROVIDER %q", c.DNSProvider))
	}
	return c, errors.Join(errs...)
}

// env возвращает переменную окружения или значение по умолчанию
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envInt читает целое число, при ошибке разбора берёт значение по умолчанию
func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

// envBool читает булево значение
func envBool(key string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

// envDuration читает длительность в формате Go (30s, 5m)
func envDuration(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return v
	}
	return def
}
