package controlplane

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/netip"
	"strings"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

var defaultSubnetV4 = netip.MustParsePrefix("10.66.0.0/20")

type createClusterRequest struct {
	Name       string        `json:"name"`
	Hostname   string        `json:"hostname"`
	ListenPort uint16        `json:"listen_port"`
	SubnetV4   *netip.Prefix `json:"subnet_v4"`
	SubnetV6   *netip.Prefix `json:"subnet_v6"`
	DNS        []string      `json:"dns"`
	MTU        int           `json:"mtu"`
	DNSMode    model.DNSMode `json:"dns_mode"`
	DNSTTL     int           `json:"dns_ttl"`
	Params     *awg.Params   `json:"params"`
}

// randomPort выбирает случайный порт 20000-59999
func randomPort() (uint16, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(40000))
	if err != nil {
		return 0, err
	}
	return uint16(20000 + n.Int64()), nil
}

// createCluster создаёт кластер с новым ключом и профилем обфускации
func (s *Server) createCluster(w http.ResponseWriter, r *http.Request) {
	var req createClusterRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Hostname = strings.TrimSuffix(strings.TrimSpace(req.Hostname), ".")
	if req.Name == "" || req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "name и hostname обязательны")
		return
	}
	c := model.Cluster{
		Name: req.Name, Hostname: req.Hostname, ListenPort: req.ListenPort,
		SubnetV4: defaultSubnetV4, DNS: req.DNS, MTU: req.MTU, DNSMode: req.DNSMode, DNSTTL: req.DNSTTL,
	}
	if req.SubnetV4 != nil {
		c.SubnetV4 = req.SubnetV4.Masked()
	}
	if req.SubnetV6 != nil {
		c.SubnetV6 = req.SubnetV6.Masked()
	}
	if !c.SubnetV4.Addr().Is4() || c.SubnetV4.Bits() > 29 {
		writeError(w, http.StatusBadRequest, "subnet_v4 должна быть IPv4-подсетью не меньше /29")
		return
	}
	if c.SubnetV6.IsValid() && (c.SubnetV6.Addr().Is4() || c.SubnetV6.Bits() > 112) {
		writeError(w, http.StatusBadRequest, "subnet_v6 должна быть IPv6-подсетью не меньше /112")
		return
	}
	if c.ListenPort == 0 {
		port, err := randomPort()
		if err != nil {
			s.writeStoreError(w, err)
			return
		}
		c.ListenPort = port
	}
	if c.MTU == 0 {
		c.MTU = 1280
	}
	if c.DNSMode == "" {
		c.DNSMode = model.DNSModeFailover
	}
	if c.DNSMode != model.DNSModeFailover && c.DNSMode != model.DNSModeAll {
		writeError(w, http.StatusBadRequest, "dns_mode: failover или all")
		return
	}
	if c.DNSTTL == 0 {
		c.DNSTTL = 60
	}
	if len(c.DNS) == 0 {
		// резолвер агента, нужен для учёта доменов
		c.DNS = []string{c.GatewayV4().String()}
	}
	var err error
	if c.PrivateKey, err = awg.GeneratePrivateKey(); err != nil {
		s.writeStoreError(w, err)
		return
	}
	c.PublicKey = c.PrivateKey.PublicKey()
	if req.Params != nil {
		c.Params = *req.Params
	} else if c.Params, err = awg.GenerateParams(); err != nil {
		s.writeStoreError(w, err)
		return
	}
	if err := c.Params.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.store.CreateCluster(r.Context(), c)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// listClusters возвращает все кластеры
func (s *Server) listClusters(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListClusters(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// getCluster возвращает кластер
func (s *Server) getCluster(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type updateClusterRequest struct {
	Hostname     *string        `json:"hostname"`
	DNS          []string       `json:"dns"`
	MTU          *int           `json:"mtu"`
	DNSMode      *model.DNSMode `json:"dns_mode"`
	DNSTTL       *int           `json:"dns_ttl"`
	ClientParams *awg.Params    `json:"client_params"`
}

// updateCluster меняет настройки, не ломающие выданные конфиги
func (s *Server) updateCluster(w http.ResponseWriter, r *http.Request) {
	var req updateClusterRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DNSMode != nil && *req.DNSMode != model.DNSModeFailover && *req.DNSMode != model.DNSModeAll {
		writeError(w, http.StatusBadRequest, "dns_mode: failover или all")
		return
	}
	if req.DNSTTL != nil && *req.DNSTTL < 60 {
		writeError(w, http.StatusBadRequest, "dns_ttl не меньше 60")
		return
	}
	out, err := s.store.UpdateCluster(r.Context(), r.PathValue("id"), store.ClusterPatch{
		Hostname: req.Hostname, DNS: req.DNS, MTU: req.MTU, DNSMode: req.DNSMode, DNSTTL: req.DNSTTL,
		ClientParams: req.ClientParams,
	})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteCluster удаляет кластер
func (s *Server) deleteCluster(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteCluster(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getClusterDNS возвращает опубликованное состояние DNS
func (s *Server) getClusterDNS(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.GetDNSState(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// syncClusterDNS немедленно пересчитывает и публикует DNS кластера
func (s *Server) syncClusterDNS(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if err := s.reconcileCluster(r.Context(), c); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("синхронизация DNS: %v", err))
		return
	}
	st, err := s.store.GetDNSState(r.Context(), c.ID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// nonNil превращает nil-слайс в пустой, чтобы API отдавал [] вместо null
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
