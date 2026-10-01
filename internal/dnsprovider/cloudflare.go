package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

type Cloudflare struct {
	token  string
	zoneID string
	http   *http.Client
}

// NewCloudflare создаёт провайдер (токен с правом Zone.DNS:Edit)
func NewCloudflare(token, zoneID string) *Cloudflare {
	return &Cloudflare{token: token, zoneID: zoneID, http: &http.Client{Timeout: 20 * time.Second}}
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// call выполняет запрос к API и разбирает result в out
func (c *Cloudflare) call(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPI+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer resp.Body.Close()
	var parsed cfResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return fmt.Errorf("cloudflare %s %s: статус %d, ответ не разобран: %w", method, path, resp.StatusCode, err)
	}
	if !parsed.Success {
		msgs := make([]string, 0, len(parsed.Errors))
		for _, e := range parsed.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return fmt.Errorf("cloudflare %s %s: %s", method, path, strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(parsed.Result, out)
	}
	return nil
}

// SetRecords сначала создаёт недостающие записи, потом удаляет лишние
func (c *Cloudflare) SetRecords(ctx context.Context, fqdn, recordType string, ips []netip.Addr, ttl int) error {
	q := url.Values{}
	q.Set("type", recordType)
	q.Set("name", fqdn)
	q.Set("per_page", "100")
	var existing []cfRecord
	if err := c.call(ctx, http.MethodGet, "/zones/"+c.zoneID+"/dns_records?"+q.Encode(), nil, &existing); err != nil {
		return err
	}
	want := make(map[string]bool, len(ips))
	for _, ip := range ips {
		want[ip.String()] = true
	}
	have := make(map[string]cfRecord, len(existing))
	for _, r := range existing {
		if addr, err := netip.ParseAddr(r.Content); err == nil {
			have[addr.String()] = r
		}
	}
	for ip := range want {
		if r, ok := have[ip]; ok {
			if r.TTL != ttl || r.Proxied {
				patch := map[string]any{"ttl": ttl, "proxied": false}
				if err := c.call(ctx, http.MethodPatch, "/zones/"+c.zoneID+"/dns_records/"+r.ID, patch, nil); err != nil {
					return err
				}
			}
			continue
		}
		rec := map[string]any{"type": recordType, "name": fqdn, "content": ip, "ttl": ttl, "proxied": false,
			"comment": "managed by amnezia-fleet"}
		if err := c.call(ctx, http.MethodPost, "/zones/"+c.zoneID+"/dns_records", rec, nil); err != nil {
			return err
		}
	}
	for ip, r := range have {
		if want[ip] {
			continue
		}
		if err := c.call(ctx, http.MethodDelete, "/zones/"+c.zoneID+"/dns_records/"+r.ID, nil, nil); err != nil {
			return err
		}
	}
	return nil
}
