// Package telemetry
package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ClickHouse struct {
	baseURL  string
	database string
	user     string
	password string
	http     *http.Client
}

// NewClickHouse создаёт клиент
func NewClickHouse(dsn string) (*ClickHouse, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("разбор DSN ClickHouse: %w", err)
	}
	c := &ClickHouse{
		baseURL:  u.Scheme + "://" + u.Host + "/",
		database: strings.Trim(u.Path, "/"),
		http:     &http.Client{Timeout: 60 * time.Second},
	}
	if c.database == "" {
		c.database = "default"
	}
	if u.User != nil {
		c.user = u.User.Username()
		c.password, _ = u.User.Password()
	}
	return c, nil
}

// do выполняет запрос
func (c *ClickHouse) do(ctx context.Context, query string, body io.Reader) (io.ReadCloser, error) {
	params := url.Values{}
	params.Set("query", query)
	params.Set("database", c.database)
	params.Set("async_insert", "1")
	params.Set("wait_for_async_insert", "1")
	params.Set("date_time_input_format", "best_effort")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"?"+params.Encode(), body)
	if err != nil {
		return nil, err
	}
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
		req.Header.Set("X-ClickHouse-Key", c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("clickhouse %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return resp.Body, nil
}

// Exec выполняет запрос без результата
func (c *ClickHouse) Exec(ctx context.Context, query string) error {
	body, err := c.do(ctx, query, nil)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, body)
	return body.Close()
}

// Insert вставляет строки в таблицу в формате JSONEachRow
func Insert[T any](ctx context.Context, c *ClickHouse, table string, rows []T) error {
	if len(rows) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	body, err := c.do(ctx, "INSERT INTO "+table+" FORMAT JSONEachRow", &buf)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, body)
	return body.Close()
}

// Select выполняет запрос и разбирает результат JSONEachRow в слайс T
func Select[T any](ctx context.Context, c *ClickHouse, query string, params map[string]string) ([]T, error) {
	values := url.Values{}
	for k, v := range params {
		values.Set("param_"+k, v)
	}
	body, err := c.doWithParams(ctx, query+" FORMAT JSONEachRow", values)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var out []T
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var row T
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("разбор строки ClickHouse: %w", err)
		}
		out = append(out, row)
	}
	return out, sc.Err()
}

// doWithParams выполняет SELECT с параметрами серверной подстановки
func (c *ClickHouse) doWithParams(ctx context.Context, query string, extra url.Values) (io.ReadCloser, error) {
	params := url.Values{}
	params.Set("database", c.database)
	params.Set("output_format_json_quote_64bit_integers", "0")
	for k, v := range extra {
		params[k] = v
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"?"+params.Encode(), strings.NewReader(query))
	if err != nil {
		return nil, err
	}
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
		req.Header.Set("X-ClickHouse-Key", c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("clickhouse %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return resp.Body, nil
}
