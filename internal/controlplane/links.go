package controlplane

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/secret"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

// linkCooldown ограничивает частоту создания устройств по одной ссылке
const linkCooldown = 5 * time.Second

// linkLimiter помнит, когда по ссылке последний раз создавали устройство
type linkLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// allow разрешает создание, если с прошлого прошло больше linkCooldown
func (l *linkLimiter) allow(userID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	if time.Since(l.last[userID]) < linkCooldown {
		return false
	}
	l.last[userID] = time.Now()
	return true
}

// linkURL собирает публичную ссылку для устройств
func linkURL(r *http.Request, token string) string {
	return serverURL(r) + "/s/" + token
}

// getUserLink возвращает текущую ссылку пользователя
func (s *Server) getUserLink(w http.ResponseWriter, r *http.Request) {
	token, err := s.store.UserLink(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	url := ""
	if token != "" {
		url = linkURL(r, token)
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": url})
}

// createUserLink выдаёт новую ссылку, прежняя перестаёт работать
func (s *Server) createUserLink(w http.ResponseWriter, r *http.Request) {
	token, hash, err := secret.NewToken()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if err := s.store.SetUserLink(r.Context(), r.PathValue("id"), token, hash); err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": linkURL(r, token)})
}

// deleteUserLink отключает ссылку
func (s *Server) deleteUserLink(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteUserLink(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// linkUser находит активного пользователя по токену из пути
func (s *Server) linkUser(w http.ResponseWriter, r *http.Request) (model.User, bool) {
	u, err := s.store.GetUserByLink(r.Context(), secret.HashToken(r.PathValue("token")))
	if err != nil {
		writeError(w, http.StatusNotFound, "ссылка недействительна")
		return model.User{}, false
	}
	if u.Status != model.UserActive || (u.ExpiresAt != nil && u.ExpiresAt.Before(time.Now())) {
		writeError(w, http.StatusForbidden, "доступ приостановлен")
		return model.User{}, false
	}
	return u, true
}

// linkPage отдаёт страницу получения ключа
func (s *Server) linkPage(w http.ResponseWriter, r *http.Request) {
	page, err := panelFS.ReadFile("panel/link.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex")
	_, _ = w.Write(page)
}

// linkDevice — устройство в ответе публичной страницы
type linkDevice struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// linkInfo отдаёт имя, устройства и лимит пользователя
func (s *Server) linkInfo(w http.ResponseWriter, r *http.Request) {
	u, ok := s.linkUser(w, r)
	if !ok {
		return
	}
	peers, err := s.store.ListPeers(r.Context(), store.PeerFilter{UserID: u.ID})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	clusters, err := s.store.ListClusters(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	devices := make([]linkDevice, 0, len(peers))
	for _, p := range peers {
		if p.Enabled && !p.PrivateKey.IsZero() {
			devices = append(devices, linkDevice{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt})
		}
	}
	type cl struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	cls := make([]cl, 0, len(clusters))
	for _, c := range clusters {
		cls = append(cls, cl{ID: c.ID, Name: c.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":     u.Name,
		"devices":  devices,
		"total":    len(peers),
		"limit":    u.DeviceLimit,
		"clusters": cls,
	})
}

// linkCreateDevice создаёт устройство в пределах лимита пользователя
func (s *Server) linkCreateDevice(w http.ResponseWriter, r *http.Request) {
	u, ok := s.linkUser(w, r)
	if !ok {
		return
	}
	var req struct {
		Name      string `json:"name"`
		ClusterID string `json:"cluster_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ClusterID == "" {
		clusters, err := s.store.ListClusters(r.Context())
		if err != nil || len(clusters) == 0 {
			writeError(w, http.StatusServiceUnavailable, "нет доступных серверов")
			return
		}
		req.ClusterID = clusters[0].ID
	}
	if !s.links.allow(u.ID) {
		writeError(w, http.StatusTooManyRequests, "подождите пару секунд")
		return
	}
	name := strings.TrimSpace(req.Name)
	if len([]rune(name)) > 40 {
		name = string([]rune(name)[:40])
	}
	p, err := newPeer(u.ID, req.ClusterID, name, nil)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	out, err := s.store.CreatePeer(r.Context(), p, true)
	if errors.Is(err, store.ErrDeviceLimit) {
		writeError(w, http.StatusConflict, "достигнут лимит устройств, удалите старое или попросите администратора")
		return
	}
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	_ = s.store.AddEvent(r.Context(), out.ClusterID, "", "link.device", fmt.Sprintf("%s подключил устройство %s по ссылке", u.Name, out.Name))
	writeJSON(w, http.StatusCreated, linkDevice{ID: out.ID, Name: out.Name, CreatedAt: out.CreatedAt})
}

// linkPeerConfig собирает конфиг устройства, проверяя, что оно принадлежит владельцу ссылки
func (s *Server) linkPeerConfig(w http.ResponseWriter, r *http.Request) (awg.ClientConfig, bool) {
	u, ok := s.linkUser(w, r)
	if !ok {
		return awg.ClientConfig{}, false
	}
	p, err := s.store.GetPeer(r.Context(), r.PathValue("id"))
	if err != nil || p.UserID != u.ID || !p.Enabled {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return awg.ClientConfig{}, false
	}
	cfg, err := s.peerClientConfigByID(r.Context(), p.ID)
	if err != nil {
		s.writeStoreError(w, err)
		return awg.ClientConfig{}, false
	}
	return cfg, true
}

// linkDeviceConfig отдаёт ссылку vpn:// или файл .conf
func (s *Server) linkDeviceConfig(w http.ResponseWriter, r *http.Request) {
	cfg, ok := s.linkPeerConfig(w, r)
	if !ok {
		return
	}
	s.writePeerConfig(w, cfg, r.URL.Query().Get("format"))
}

// linkDeviceQR отдаёт QR-код ссылки vpn://
func (s *Server) linkDeviceQR(w http.ResponseWriter, r *http.Request) {
	cfg, ok := s.linkPeerConfig(w, r)
	if !ok {
		return
	}
	writeQR(w, cfg)
}

// writeQR рисует QR-код ссылки vpn:// в PNG
func writeQR(w http.ResponseWriter, cfg awg.ClientConfig) {
	url, err := cfg.AmneziaURL()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "внутренняя ошибка")
		return
	}
	code, err := qr.Encode(url, qr.L)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "ссылка не помещается в QR-код")
		return
	}
	code.Scale = 4
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(code.PNG())
}
