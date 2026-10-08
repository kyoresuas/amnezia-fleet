package controlplane

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/secret"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

// youtubeDomains идут через выход по умолчанию
var youtubeDomains = []string{
	"youtube.com", "youtu.be", "youtube-nocookie.com", "youtubekids.com",
	"googlevideo.com", "ytimg.com", "ggpht.com",
	"youtubei.googleapis.com", "youtube.googleapis.com", "yt.be",
}

// exitWithToken, ответ при создании выхода, токен показывается один раз
type exitWithToken struct {
	model.Exit
	Token string `json:"token"`
}

// createExit заводит выход для кластера
func (s *Server) createExit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string     `json:"name"`
		Endpoint   netip.Addr `json:"endpoint"`
		ListenPort uint16     `json:"listen_port"`
		Domains    []string   `json:"domains"`
		DNS        string     `json:"dns"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !req.Endpoint.IsValid() || req.Endpoint.IsPrivate() {
		writeError(w, http.StatusBadRequest, "endpoint должен быть публичным IP")
		return
	}
	e := model.Exit{
		ClusterID:  r.PathValue("id"),
		Name:       strings.TrimSpace(req.Name),
		Endpoint:   req.Endpoint,
		ListenPort: req.ListenPort,
		SubnetV4:   netip.MustParsePrefix("10.67.0.0/24"),
		DNS:        req.DNS,
		Domains:    normalizeDomains(req.Domains),
	}
	if e.Name == "" {
		e.Name = "exit"
	}
	if e.DNS == "" {
		e.DNS = "77.88.8.8"
	}
	if _, err := netip.ParseAddr(e.DNS); err != nil {
		writeError(w, http.StatusBadRequest, "dns должен быть IP")
		return
	}
	if len(e.Domains) == 0 {
		e.Domains = youtubeDomains
	}
	var err error
	if e.ListenPort == 0 {
		if e.ListenPort, err = randomPort(); err != nil {
			s.writeStoreError(w, err)
			return
		}
	}
	if e.PrivateKey, err = awg.GeneratePrivateKey(); err != nil {
		s.writeStoreError(w, err)
		return
	}
	e.PublicKey = e.PrivateKey.PublicKey()
	if e.Params, err = awg.GenerateParams(); err != nil {
		s.writeStoreError(w, err)
		return
	}
	token, hash, err := secret.NewToken()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	out, err := s.store.CreateExit(r.Context(), e, hash)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	_ = s.store.AddEvent(r.Context(), out.ClusterID, "", "exit.created", fmt.Sprintf("выход %s через %s", out.Name, out.Endpoint))
	writeJSON(w, http.StatusCreated, exitWithToken{Exit: out, Token: token})
}

// normalizeDomains приводит домены к нижнему регистру без точек по краям и повторов
func normalizeDomains(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// getExit возвращает выход кластера
func (s *Server) getExit(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.GetExitByCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// updateExit включает и выключает выход или меняет список доменов
func (s *Server) updateExit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool    `json:"enabled"`
		Domains []string `json:"domains"`
		DNS     *string  `json:"dns"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DNS != nil {
		if _, err := netip.ParseAddr(*req.DNS); err != nil {
			writeError(w, http.StatusBadRequest, "dns должен быть IP")
			return
		}
	}
	var domains []string
	if req.Domains != nil {
		if domains = normalizeDomains(req.Domains); len(domains) == 0 {
			writeError(w, http.StatusBadRequest, "нужен хотя бы один домен")
			return
		}
	}
	out, err := s.store.UpdateExit(r.Context(), r.PathValue("id"), store.ExitPatch{Enabled: req.Enabled, Domains: domains, DNS: req.DNS})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteExit удаляет выход, узлы снимают маршрут при следующем применении
func (s *Server) deleteExit(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteExit(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// exitState отдаёт конфигурацию самому выходу
func (s *Server) exitState(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "нужен токен выхода")
		return
	}
	e, err := s.store.GetExitByTokenHash(r.Context(), secret.HashToken(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "неверный токен выхода")
		return
	}
	links, err := s.store.ListExitLinks(r.Context(), e.ID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	st := agentapi.ExitState{
		PrivateKey: e.PrivateKey,
		ListenPort: e.ListenPort,
		Address:    netip.PrefixFrom(e.SubnetV4.Masked().Addr().Next(), e.SubnetV4.Bits()),
		Params:     e.Params,
		Peers:      make([]agentapi.ExitPeer, 0, len(links)),
	}
	if e.Enabled {
		for _, l := range links {
			st.Peers = append(st.Peers, agentapi.ExitPeer{PublicKey: l.PublicKey, Address: l.Address})
		}
	}
	writeJSON(w, http.StatusOK, st)
}
