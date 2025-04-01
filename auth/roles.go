package auth

import (
	"context"
	"net/http"
)

func RequireRole(required string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := r.Context().Value(ContextRole)
			if role != required {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireAnyRole(allowed ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(ContextRole).(string)
			if !ok {
				http.Error(w, "missing role", http.StatusForbidden)
				return
			}

			for _, allowedRole := range allowed {
				if role == allowedRole {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}

func MustBeAuthenticated() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(ContextUserID) == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ExtractUserID(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(ContextUserID).(int64)
	return id, ok
}

func ExtractRole(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(ContextRole).(string)
	return role, ok
}

func IsAdmin(ctx context.Context) bool {
	role, ok := ExtractRole(ctx)
	return ok && role == "admin"
}
