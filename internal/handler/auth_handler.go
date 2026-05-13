package handler

import (
	"encoding/json"
	"net/http"
	"network-monitor-backend/internal/httpx"
	"network-monitor-backend/internal/service"
)

type AuthHandler struct{ auth *service.AuthService }

func NewAuthHandler(auth *service.AuthService) *AuthHandler { return &AuthHandler{auth: auth} }
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "INVALID_JSON", "Invalid JSON body", nil)
		return
	}
	token, exp, u, err := h.auth.Login(r.Context(), req.Login, req.Password)
	if err != nil {
		httpx.Error(w, 401, "INVALID_CREDENTIALS", "Invalid login or password", nil)
		return
	}
	httpx.JSON(w, 200, map[string]any{"token": token, "expires_at": exp, "user": map[string]any{"id": u.ID, "login": u.Login, "role": u.Role}})
}
