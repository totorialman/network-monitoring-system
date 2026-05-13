package middleware

import (
	"context"
	"github.com/google/uuid"
	"net/http"
	"network-monitor-backend/internal/domain"
	"network-monitor-backend/internal/httpx"
	"network-monitor-backend/internal/pkg/hash"
	jwtutil "network-monitor-backend/internal/pkg/jwt"
	"strings"
)

type ctxKey string

const UserKey ctxKey = "user"
const AgentKey ctxKey = "agent"

type Middleware func(http.Handler) http.Handler
type AgentRepository interface {
	FindByTokenHash(context.Context, string) (*domain.Agent, error)
	Touch(context.Context, uuid.UUID)
}

func JWT(secret string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearer(r)
			if token == "" {
				httpx.Error(w, http.StatusUnauthorized, "AUTH_REQUIRED", "Valid authorization token required", nil)
				return
			}
			claims, err := jwtutil.Parse(token, secret)
			if err != nil {
				httpx.Error(w, http.StatusUnauthorized, "AUTH_REQUIRED", "Valid authorization token required", nil)
				return
			}
			ctx := context.WithValue(r.Context(), UserKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
func AgentAuth(repo AgentRepository) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearer(r)
			if token == "" {
				httpx.Error(w, http.StatusUnauthorized, "INVALID_TOKEN", "Agent token is invalid or revoked", nil)
				return
			}
			a, err := repo.FindByTokenHash(r.Context(), hash.SHA256(token))
			if err != nil || a == nil {
				httpx.Error(w, http.StatusUnauthorized, "INVALID_TOKEN", "Agent token is invalid or revoked", nil)
				return
			}
			repo.Touch(r.Context(), a.ID)
			ctx := context.WithValue(r.Context(), AgentKey, a)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}
