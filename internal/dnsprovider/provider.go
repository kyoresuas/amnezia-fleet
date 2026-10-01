// Package dnsprovider
package dnsprovider

import (
	"context"
	"log/slog"
	"net/netip"
)

type Provider interface {
	// SetRecords приводит записи fqdn к списку ips
	SetRecords(ctx context.Context, fqdn, recordType string, ips []netip.Addr, ttl int) error
}

type Noop struct {
	Log *slog.Logger
}

// SetRecords пишет желаемое состояние в журнал
func (n Noop) SetRecords(_ context.Context, fqdn, recordType string, ips []netip.Addr, ttl int) error {
	n.Log.Info("dns: желаемые записи (провайдер не настроен)", "fqdn", fqdn, "type", recordType, "ips", ips, "ttl", ttl)
	return nil
}
