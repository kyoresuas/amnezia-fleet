package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

type createUserRequest struct {
	Name              string     `json:"name"`
	Note              string     `json:"note"`
	TrafficLimitBytes *int64     `json:"traffic_limit_bytes"`
	ExpiresAt         *time.Time `json:"expires_at"`
}

// createUser создаёт пользователя
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name обязателен")
		return
	}
	out, err := s.store.CreateUser(r.Context(), model.User{
		Name: req.Name, Note: req.Note, TrafficLimitBytes: req.TrafficLimitBytes, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// listUsers возвращает всех пользователей
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// getUser возвращает пользователя
func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// updateUser меняет пользователя
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	// чтобы отличить null от отсутствующего поля
	var raw map[string]json.RawMessage
	if err := readJSON(r, &raw); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var p store.UserPatch
	for key, val := range raw {
		var err error
		switch key {
		case "name":
			err = json.Unmarshal(val, &p.Name)
		case "note":
			err = json.Unmarshal(val, &p.Note)
		case "status":
			err = json.Unmarshal(val, &p.Status)
			if err == nil && p.Status != nil && *p.Status != model.UserActive && *p.Status != model.UserSuspended {
				err = fmt.Errorf("status: active или suspended")
			}
		case "traffic_limit_bytes":
			var v *int64
			err = json.Unmarshal(val, &v)
			p.TrafficLimitBytes = &v
		case "expires_at":
			var v *time.Time
			err = json.Unmarshal(val, &v)
			p.ExpiresAt = &v
		default:
			err = fmt.Errorf("неизвестное поле %q", key)
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	out, err := s.store.UpdateUser(r.Context(), r.PathValue("id"), p)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteUser удаляет пользователя и все его пиры
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteUser(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listUserPeers возвращает пиров пользователя
func (s *Server) listUserPeers(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListPeers(r.Context(), store.PeerFilter{UserID: r.PathValue("id")})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

type createPeerRequest struct {
	ClusterID string   `json:"cluster_id"`
	Name      string   `json:"name"`
	PublicKey *awg.Key `json:"public_key"`
}

// createPeer создаёт пира с собственным PSK и адресом в подсети кластера
func (s *Server) createPeer(w http.ResponseWriter, r *http.Request) {
	var req createPeerRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ClusterID == "" {
		writeError(w, http.StatusBadRequest, "cluster_id обязателен")
		return
	}
	p := model.Peer{UserID: r.PathValue("id"), ClusterID: req.ClusterID, Name: strings.TrimSpace(req.Name)}
	if p.Name == "" {
		p.Name = "device"
	}
	var err error
	if req.PublicKey != nil && !req.PublicKey.IsZero() {
		p.PublicKey = *req.PublicKey
	} else {
		if p.PrivateKey, err = awg.GeneratePrivateKey(); err != nil {
			s.writeStoreError(w, err)
			return
		}
		p.PublicKey = p.PrivateKey.PublicKey()
	}
	if p.PresharedKey, err = awg.GenerateSymmetricKey(); err != nil {
		s.writeStoreError(w, err)
		return
	}
	out, err := s.store.CreatePeer(r.Context(), p)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// getPeer возвращает пира
func (s *Server) getPeer(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetPeer(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type updatePeerRequest struct {
	Enabled *bool `json:"enabled"`
}

// updatePeer включает или отключает пира
func (s *Server) updatePeer(w http.ResponseWriter, r *http.Request) {
	var req updatePeerRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled обязателен")
		return
	}
	out, err := s.store.SetPeerEnabled(r.Context(), r.PathValue("id"), *req.Enabled)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// deletePeer удаляет пира
func (s *Server) deletePeer(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeletePeer(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var unsafeFileChars = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// getPeerConfig выдаёт конфиг пира (format=amnezia или conf)
func (s *Server) getPeerConfig(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetPeer(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if p.PrivateKey.IsZero() {
		writeError(w, http.StatusConflict, "приватный ключ пира неизвестен (ключ передан клиентом)")
		return
	}
	c, err := s.store.GetCluster(r.Context(), p.ClusterID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	cfg := awg.ClientConfig{
		Description:     c.Name,
		Host:            c.Hostname,
		Port:            c.ListenPort,
		ServerPublicKey: c.PublicKey,
		PrivateKey:      p.PrivateKey,
		PresharedKey:    p.PresharedKey,
		AddressV4:       p.AddressV4,
		AddressV6:       p.AddressV6,
		Subnet:          c.SubnetV4,
		DNS:             c.DNS,
		MTU:             c.MTU,
		Params:          c.Params,
	}
	switch r.URL.Query().Get("format") {
	case "", "amnezia":
		url, err := cfg.AmneziaURL()
		if err != nil {
			s.writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"url": url})
	case "conf":
		name := unsafeFileChars.ReplaceAllString(c.Name+"-"+p.Name, "_")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, name))
		_, _ = w.Write([]byte(cfg.NativeConf()))
	default:
		writeError(w, http.StatusBadRequest, "format: amnezia или conf")
	}
}
