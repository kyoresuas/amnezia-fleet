package controlplane

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/dnsprovider"
	"github.com/kyoresuas/amnezia-fleet/internal/ipam"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/secret"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
	"github.com/kyoresuas/amnezia-fleet/internal/telemetry"
)

type Server struct {
	cfg   Config
	store *store.Store
	// nil без ClickHouse
	tele         *telemetry.Repo
	dns          dnsprovider.Provider
	log          *slog.Logger
	online       *onlineTracker
	noCandidates flagSet
	links        linkLimiter
}

// NewServer собирает сервер из зависимостей
func NewServer(cfg Config, st *store.Store, tele *telemetry.Repo, dns dnsprovider.Provider, log *slog.Logger) *Server {
	return &Server{cfg: cfg, store: st, tele: tele, dns: dns, log: log, online: newOnlineTracker()}
}

// Handler возвращает корневой обработчик со всеми маршрутами
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	admin := http.NewServeMux()
	admin.HandleFunc("GET /api/v1/clusters", s.listClusters)
	admin.HandleFunc("POST /api/v1/clusters", s.createCluster)
	admin.HandleFunc("GET /api/v1/clusters/{id}", s.getCluster)
	admin.HandleFunc("PATCH /api/v1/clusters/{id}", s.updateCluster)
	admin.HandleFunc("DELETE /api/v1/clusters/{id}", s.deleteCluster)
	admin.HandleFunc("GET /api/v1/clusters/{id}/dns", s.getClusterDNS)
	admin.HandleFunc("POST /api/v1/clusters/{id}/dns/sync", s.syncClusterDNS)
	admin.HandleFunc("POST /api/v1/clusters/{id}/dns/publish", s.publishAddress)
	admin.HandleFunc("GET /api/v1/clusters/{id}/online", s.clusterOnline)
	admin.HandleFunc("GET /api/v1/clusters/{id}/exit", s.getExit)
	admin.HandleFunc("POST /api/v1/clusters/{id}/exit", s.createExit)
	admin.HandleFunc("PATCH /api/v1/exits/{id}", s.updateExit)
	admin.HandleFunc("DELETE /api/v1/exits/{id}", s.deleteExit)

	admin.HandleFunc("GET /api/v1/clusters/{id}/nodes", s.listNodes)
	admin.HandleFunc("POST /api/v1/clusters/{id}/nodes", s.createNode)
	admin.HandleFunc("GET /api/v1/nodes/{id}", s.getNode)
	admin.HandleFunc("PATCH /api/v1/nodes/{id}", s.updateNode)
	admin.HandleFunc("DELETE /api/v1/nodes/{id}", s.deleteNode)
	admin.HandleFunc("POST /api/v1/nodes/{id}/token", s.rotateNodeToken)
	admin.HandleFunc("POST /api/v1/nodes/{id}/addresses", s.addAddress)
	admin.HandleFunc("PATCH /api/v1/addresses/{id}", s.updateAddress)
	admin.HandleFunc("DELETE /api/v1/addresses/{id}", s.deleteAddress)

	admin.HandleFunc("GET /api/v1/users", s.listUsers)
	admin.HandleFunc("POST /api/v1/users", s.createUser)
	admin.HandleFunc("GET /api/v1/users/{id}", s.getUser)
	admin.HandleFunc("PATCH /api/v1/users/{id}", s.updateUser)
	admin.HandleFunc("DELETE /api/v1/users/{id}", s.deleteUser)
	admin.HandleFunc("GET /api/v1/users/{id}/peers", s.listUserPeers)
	admin.HandleFunc("POST /api/v1/users/{id}/peers", s.createPeer)
	admin.HandleFunc("GET /api/v1/users/{id}/link", s.getUserLink)
	admin.HandleFunc("POST /api/v1/users/{id}/link", s.createUserLink)
	admin.HandleFunc("DELETE /api/v1/users/{id}/link", s.deleteUserLink)

	admin.HandleFunc("GET /api/v1/meta", s.meta)
	admin.HandleFunc("GET /api/v1/peers", s.listAllPeers)
	admin.HandleFunc("GET /api/v1/peers/{id}/qr", s.peerQR)
	admin.HandleFunc("GET /api/v1/peers/{id}", s.getPeer)
	admin.HandleFunc("PATCH /api/v1/peers/{id}", s.updatePeer)
	admin.HandleFunc("DELETE /api/v1/peers/{id}", s.deletePeer)
	admin.HandleFunc("GET /api/v1/peers/{id}/config", s.getPeerConfig)

	admin.HandleFunc("GET /api/v1/probes", s.listProbes)
	admin.HandleFunc("POST /api/v1/probes", s.createProbe)
	admin.HandleFunc("DELETE /api/v1/probes/{id}", s.deleteProbe)
	admin.HandleFunc("GET /api/v1/probes/status", s.probeStatus)

	admin.HandleFunc("GET /api/v1/stats/usage", s.statsUsage)
	admin.HandleFunc("GET /api/v1/users/{id}/usage", s.userUsage)
	admin.HandleFunc("GET /api/v1/users/{id}/destinations", s.userDestinations)
	admin.HandleFunc("GET /api/v1/users/{id}/dns", s.userDNSLog)
	admin.HandleFunc("GET /api/v1/events", s.listEvents)

	mux.Handle("/api/", s.requireAdmin(admin))
	mux.Handle("GET /panel/", s.panelHandler())
	mux.HandleFunc("GET /{$}", redirectPanel)
	mux.HandleFunc("GET /s/{token}", s.linkPage)
	mux.HandleFunc("GET /s/{token}/info", s.linkInfo)
	mux.HandleFunc("POST /s/{token}/devices", s.linkCreateDevice)
	mux.HandleFunc("GET /s/{token}/devices/{id}/config", s.linkDeviceConfig)
	mux.HandleFunc("GET /s/{token}/devices/{id}/qr", s.linkDeviceQR)
	mux.HandleFunc("GET /install.sh", s.installScript)
	mux.HandleFunc("GET /uninstall.sh", s.uninstallScript)
	mux.HandleFunc("GET /dist/{name}", s.distFile)
	mux.HandleFunc("GET /agent/v1/state", s.agentState)
	mux.HandleFunc("POST /agent/v1/report", s.agentReport)
	mux.HandleFunc("GET /exit/v1/state", s.exitState)
	mux.HandleFunc("GET /probe/v1/targets", s.probeTargets)
	mux.HandleFunc("POST /probe/v1/results", s.probeResults)

	return s.logRequests(mux)
}

// handleHealthz отвечает 200, если база доступна
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "postgres недоступен")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// bearer извлекает токен из заголовка Authorization
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(t)
	}
	return ""
}

// requireAdmin пропускает только запросы с админским токеном
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !secret.EqualToken(bearer(r), s.cfg.AdminToken) {
			writeError(w, http.StatusUnauthorized, "нужен админский токен")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authNode находит узел по токену агента
func (s *Server) authNode(r *http.Request) (model.Node, bool) {
	token := bearer(r)
	if token == "" {
		return model.Node{}, false
	}
	n, err := s.store.GetNodeByTokenHash(r.Context(), secret.HashToken(token))
	return n, err == nil
}

// authProbe находит наблюдателя по токену
func (s *Server) authProbe(r *http.Request) (model.Probe, bool) {
	token := bearer(r)
	if token == "" {
		return model.Probe{}, false
	}
	p, err := s.store.GetProbeByTokenHash(r.Context(), secret.HashToken(token))
	return p, err == nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader сохраняет код ответа
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// logRequests пишет в журнал ошибочные и медленные запросы
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status >= 400 || (time.Since(start) > 2*time.Second && r.URL.Path != "/agent/v1/state") {
			s.log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "dur", time.Since(start).Round(time.Millisecond))
		}
	})
}

const maxBodyBytes = 32 << 20

// readJSON разбирает тело запроса, в том числе gzip
func readJSON(r *http.Request, v any) error {
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return err
		}
		defer gz.Close()
		body = gz
	}
	dec := json.NewDecoder(io.LimitReader(body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// writeJSON отправляет JSON-ответ
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError отправляет ошибку в едином формате
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeStoreError переводит ошибку хранилища в HTTP-статус
func (s *Server) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "не найдено")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ipam.ErrExhausted), errors.Is(err, errNoPrivateKey), errors.Is(err, store.ErrDeviceLimit):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.log.Error("внутренняя ошибка", "err", err)
		writeError(w, http.StatusInternalServerError, "внутренняя ошибка")
	}
}
