package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/Sergentval/gametunnel/internal/config"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const agentIDKey contextKey = "agentID"

// AgentIDFromContext extracts the authenticated agent ID from the context.
// Returns an empty string if no agent ID is present.
func AgentIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(agentIDKey).(string)
	return v
}

// AuthMiddleware returns a middleware that validates the Bearer token in the
// Authorization header. On success the authenticated agent's ID is stored in
// the request context. On failure it writes a 401 JSON error.
func AuthMiddleware(cfg *config.ServerConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid Authorization header"})
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			entry := cfg.AgentByToken(token)
			if entry == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}

			ctx := context.WithValue(r.Context(), agentIDKey, entry.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
