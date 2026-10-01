package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
)

var errNotModified = errors.New("состояние не изменилось")

type apiClient struct {
	base  string
	token string
	http  *http.Client
}

// newAPIClient создаёт клиент
func newAPIClient(base, token string) *apiClient {
	return &apiClient{base: base, token: token, http: &http.Client{Timeout: 60 * time.Second}}
}

// fetchState запрашивает желаемое состояние
func (c *apiClient) fetchState(ctx context.Context, known int64) (agentapi.DesiredState, error) {
	var st agentapi.DesiredState
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+agentapi.PathState, nil)
	if err != nil {
		return st, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if known > 0 {
		req.Header.Set(agentapi.HeaderKnownRevision, strconv.FormatInt(known, 10))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		err = json.NewDecoder(resp.Body).Decode(&st)
		return st, err
	case http.StatusNotModified:
		return st, errNotModified
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return st, fmt.Errorf("state: %d %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
}

// sendReport отправляет отчёт со сжатием
func (c *apiClient) sendReport(ctx context.Context, rep agentapi.Report) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(rep); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+agentapi.PathReport, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("report: %d %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}
