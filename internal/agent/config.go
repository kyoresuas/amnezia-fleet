// Package agent
package agent

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Version подставляется при сборке через -ldflags
var Version = "dev"

type Config struct {
	ServerURL        string
	Token            string
	Iface            string
	StateFile        string
	DNSUpstreams     []string
	ReportEvery      time.Duration
	FlowsEvery       time.Duration
	MaxBufferedFlows int
	MaxBufferedDNS   int
}

// LoadConfig читает конфигурацию агента
func LoadConfig() (Config, error) {
	c := Config{
		ServerURL:        strings.TrimRight(os.Getenv("FLEET_SERVER_URL"), "/"),
		Token:            os.Getenv("FLEET_AGENT_TOKEN"),
		Iface:            envOr("FLEET_IFACE", "awgf0"),
		StateFile:        envOr("FLEET_STATE_FILE", "/var/lib/fleet-agent/state.json"),
		DNSUpstreams:     strings.Split(envOr("FLEET_DNS_UPSTREAMS", "1.1.1.1:53,9.9.9.9:53"), ","),
		ReportEvery:      envDuration("FLEET_REPORT_EVERY", 30*time.Second),
		FlowsEvery:       envDuration("FLEET_FLOWS_EVERY", 30*time.Second),
		MaxBufferedFlows: envInt("FLEET_MAX_BUFFERED_FLOWS", 200000),
		MaxBufferedDNS:   envInt("FLEET_MAX_BUFFERED_DNS", 100000),
	}
	var errs []error
	if c.ServerURL == "" {
		errs = append(errs, errors.New("FLEET_SERVER_URL не задан"))
	}
	if c.Token == "" {
		errs = append(errs, errors.New("FLEET_AGENT_TOKEN не задан"))
	}
	if len(c.Iface) > 15 {
		errs = append(errs, errors.New("FLEET_IFACE длиннее 15 символов"))
	}
	return c, errors.Join(errs...)
}

// envOr возвращает переменную окружения или значение по умолчанию
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envInt читает целое число
func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}

// envDuration читает длительность
func envDuration(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}
