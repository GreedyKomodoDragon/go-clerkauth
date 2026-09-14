package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/clerk/clerk-sdk-go/v2"

	"github.com/GreedyKomodoDragon/go-clerkauth/userinfo"
)

// contextKey is the request-context key for UserInfo.
type contextKey struct{}

// DeletionCheck reports whether userID is blocked (suspended/pending deletion).
// It stays app-specific; the service passes its DB-backed implementation.
type DeletionCheck func(ctx context.Context, userID string) (blocked bool, status string, err error)

// Middleware wires JWT verification into HTTP handlers.
type Middleware struct {
	opts          userinfo.AuthOptions
	resolver      userinfo.GitHubUsernameResolver
	deletionCheck DeletionCheck
}

// InitClerk sets the global Clerk secret key once (required by clerk-sdk-go jwt.Verify).
func InitClerk(secretKey string) {
	if secretKey != "" {
		clerk.SetKey(secretKey)
	}
}

// NewMiddleware builds a Middleware. Call InitClerk (or clerk.SetKey) with the
// secret key before serving, or pass it via opts and call InitClerk here.
func NewMiddleware(opts userinfo.AuthOptions, resolver userinfo.GitHubUsernameResolver, check DeletionCheck) *Middleware {
	InitClerk(opts.SecretKey)
	return &Middleware{opts: opts, resolver: resolver, deletionCheck: check}
}

// GetUserInfo extracts UserInfo from the request context.
func GetUserInfo(r *http.Request) (*userinfo.UserInfo, bool) {
	info, ok := r.Context().Value(contextKey{}).(*userinfo.UserInfo)
	return info, ok
}

func withUserInfo(r *http.Request, info *userinfo.UserInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey{}, info))
}

func sendUnauthorized(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := strings.ToLower(strings.TrimSpace(r.Host))
	if host == "" || strings.ContainsAny(host, "\r\n") {
		host = "localhost:8080"
	}
	realm := fmt.Sprintf("%s://%s/v2/token", scheme, host)
	w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s"`, realm))
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// ClerkAuth accepts Clerk JWT (Bearer) or registry tokens via verifyRegistry.
// Pass nil verifyRegistry to accept Clerk JWT only for the bearer branch.
func (m *Middleware) ClerkAuth(verifyRegistry func(token string, r *http.Request) (*userinfo.UserInfo, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 {
				sendUnauthorized(w, r)
				return
			}
			authType := strings.ToLower(parts[0])
			credentials := parts[1]

			var info *userinfo.UserInfo
			var err error
			switch authType {
			case "bearer":
				info, err = Verify(r.Context(), credentials, m.opts, m.resolver)
				if err != nil {
					sendUnauthorized(w, r)
					return
				}
			case "basic":
				if verifyRegistry == nil {
					sendUnauthorized(w, r)
					return
				}
				info, err = verifyRegistry(credentials, r)
				if err != nil {
					sendUnauthorized(w, r)
					return
				}
			default:
				sendUnauthorized(w, r)
				return
			}

			if m.deletionCheck != nil {
				if blocked, _, err := m.deletionCheck(r.Context(), info.UserID); err != nil {
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				} else if blocked {
					sendUnauthorized(w, r)
					return
				}
			}
			next.ServeHTTP(w, withUserInfo(r, info))
		})
	}
}

// ClerkJWTOnly restricts access to Clerk JWT (Bearer) tokens only.
func (m *Middleware) ClerkJWTOnly(allowStatusPaths ...string) func(http.Handler) http.Handler {
	allow := map[string]bool{}
	for _, p := range allowStatusPaths {
		allow[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				sendUnauthorized(w, r)
				return
			}
			info, err := Verify(r.Context(), parts[1], m.opts, m.resolver)
			if err != nil {
				sendUnauthorized(w, r)
				return
			}
			if m.deletionCheck != nil {
				path := strings.TrimSuffix(r.URL.Path, "/")
				if blocked, _, err := m.deletionCheck(r.Context(), info.UserID); err != nil {
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				} else if blocked && !allow[path] {
					http.Error(w, "user suspended or pending deletion", http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, withUserInfo(r, info))
		})
	}
}
