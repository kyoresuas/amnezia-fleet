package controlplane

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/secret"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

type createProbeRequest struct {
	Name   string `json:"name"`
	Region string `json:"region"`
}

type probeCredentials struct {
	model.Probe
	PrivateKey awg.Key `json:"private_key"`
	Token      string  `json:"token"`
}

// createProbe регистрирует наблюдателя и выдаёт ему ключ AWG и токен API
func (s *Server) createProbe(w http.ResponseWriter, r *http.Request) {
	var req createProbeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name обязателен")
		return
	}
	priv, err := awg.GeneratePrivateKey()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	token, hash, err := secret.NewToken()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	p, err := s.store.CreateProbe(r.Context(), req.Name, req.Region, priv.PublicKey(), hash)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, probeCredentials{Probe: p, PrivateKey: priv, Token: token})
}

// listProbes возвращает наблюдателей
func (s *Server) listProbes(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListProbes(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// deleteProbe удаляет наблюдателя
func (s *Server) deleteProbe(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteProbe(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// probeStatus возвращает свежие результаты всех наблюдателей
func (s *Server) probeStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListProbeStatuses(r.Context(), s.probeFreshness())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// probeTargets отдаёт наблюдателю список адресов с параметрами их кластеров
func (s *Server) probeTargets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authProbe(r); !ok {
		writeError(w, http.StatusUnauthorized, "неверный токен наблюдателя")
		return
	}
	targets, err := s.store.ListProbeTargets(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	out := agentapi.ProbeTargets{IntervalSeconds: int(s.cfg.ProbeInterval.Seconds())}
	for _, t := range targets {
		out.Targets = append(out.Targets, agentapi.ProbeTarget{
			AddressID:       t.AddressID,
			ClusterID:       t.ClusterID,
			Endpoint:        netip.AddrPortFrom(t.IP, t.Port),
			ServerPublicKey: t.ServerPublicKey,
			Params:          t.Params,
		})
	}
	out.Targets = nonNil(out.Targets)
	writeJSON(w, http.StatusOK, out)
}

// probeResults принимает результаты проверок
func (s *Server) probeResults(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authProbe(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "неверный токен наблюдателя")
		return
	}
	var req agentapi.ProbeResults
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	results := make([]store.ProbeResult, len(req.Results))
	for i, res := range req.Results {
		results[i] = store.ProbeResult{AddressID: res.AddressID, OK: res.OK, RTTMs: res.RTTMs, Error: res.Error}
	}
	if err := s.store.RecordProbeResults(r.Context(), p.ID, results); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
