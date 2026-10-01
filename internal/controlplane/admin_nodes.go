package controlplane

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/secret"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

type createNodeRequest struct {
	Name      string       `json:"name"`
	Addresses []netip.Addr `json:"addresses"`
}

type nodeWithToken struct {
	model.Node
	AgentToken string `json:"agent_token"`
}

// createNode регистрирует узел в кластере и выдаёт токен агента
func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	var req createNodeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Addresses) == 0 {
		writeError(w, http.StatusBadRequest, "name и хотя бы один адрес обязательны")
		return
	}
	for _, a := range req.Addresses {
		if !a.IsGlobalUnicast() || a.IsPrivate() {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("адрес %s не публичный", a))
			return
		}
	}
	token, hash, err := secret.NewToken()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	n, err := s.store.CreateNode(r.Context(), r.PathValue("id"), req.Name, hash, req.Addresses)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	_ = s.store.AddEvent(r.Context(), n.ClusterID, n.ID, "node.created", "узел "+n.Name+" зарегистрирован")
	writeJSON(w, http.StatusCreated, nodeWithToken{Node: n, AgentToken: token})
}

// listNodes возвращает узлы кластера
func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListNodes(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// getNode возвращает узел
func (s *Server) getNode(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetNode(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type updateNodeRequest struct {
	State model.NodeState `json:"state"`
}

// updateNode меняет состояние узла (active, draining, disabled)
func (s *Server) updateNode(w http.ResponseWriter, r *http.Request) {
	var req updateNodeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch req.State {
	case model.NodeActive, model.NodeDraining, model.NodeDisabled:
	default:
		writeError(w, http.StatusBadRequest, "state: active, draining или disabled")
		return
	}
	id := r.PathValue("id")
	if err := s.store.SetNodeState(r.Context(), id, req.State); err != nil {
		s.writeStoreError(w, err)
		return
	}
	out, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	_ = s.store.AddEvent(r.Context(), out.ClusterID, out.ID, "node.state", "состояние узла "+out.Name+": "+string(req.State))
	writeJSON(w, http.StatusOK, out)
}

// deleteNode удаляет узел
func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteNode(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotateNodeToken выдаёт новый токен агента, старый перестаёт работать сразу
func (s *Server) rotateNodeToken(w http.ResponseWriter, r *http.Request) {
	token, hash, err := secret.NewToken()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if err := s.store.RotateNodeToken(r.Context(), r.PathValue("id"), hash); err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"agent_token": token})
}

type addAddressRequest struct {
	IP       netip.Addr         `json:"ip"`
	State    model.AddressState `json:"state"`
	Priority int                `json:"priority"`
}

// validAddressState проверяет допустимое состояние адреса
func validAddressState(st model.AddressState) bool {
	switch st {
	case model.AddressActive, model.AddressSpare, model.AddressBlocked, model.AddressDisabled:
		return true
	}
	return false
}

// addAddress добавляет узлу адрес
func (s *Server) addAddress(w http.ResponseWriter, r *http.Request) {
	var req addAddressRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !req.IP.IsGlobalUnicast() || req.IP.IsPrivate() {
		writeError(w, http.StatusBadRequest, "адрес не публичный")
		return
	}
	if req.State == "" {
		req.State = model.AddressSpare
	}
	if !validAddressState(req.State) {
		writeError(w, http.StatusBadRequest, "state: active, spare, blocked или disabled")
		return
	}
	if req.Priority == 0 {
		req.Priority = 200
	}
	out, err := s.store.AddAddress(r.Context(), r.PathValue("id"), req.IP, req.State, req.Priority)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

type updateAddressRequest struct {
	State    *model.AddressState `json:"state"`
	Priority *int                `json:"priority"`
}

// updateAddress меняет состояние или приоритет адреса
func (s *Server) updateAddress(w http.ResponseWriter, r *http.Request) {
	var req updateAddressRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.State != nil && !validAddressState(*req.State) {
		writeError(w, http.StatusBadRequest, "state: active, spare, blocked или disabled")
		return
	}
	out, err := s.store.UpdateAddress(r.Context(), r.PathValue("id"), store.AddressPatch{State: req.State, Priority: req.Priority})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if req.State != nil {
		_ = s.store.AddEvent(r.Context(), "", out.NodeID, "address.state", "адрес "+out.IP.String()+": "+string(*req.State))
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteAddress удаляет адрес узла
func (s *Server) deleteAddress(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAddress(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
