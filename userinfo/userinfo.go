// Package userinfo holds the shared identity contract for Clerk auth.
//
// It intentionally has zero third-party dependencies so both the cache
// (Redis username resolver) and auth (JWT middleware) packages — and any
// consuming service — can share UserInfo without import cycles.
package userinfo

import "context"

// AuthType identifies how the caller authenticated.
type AuthType string

const (
	AuthTypeClerk AuthType = "clerk"
	AuthTypeToken AuthType = "token"
)

// UserInfo is the authenticated identity attached to a request context.
type UserInfo struct {
	UserID        string
	Username      string
	AccessKeyName string
	Email         string
	AuthType      AuthType
	Emails        []string
}

// GitHubUsernameResolver resolves a Clerk user ID to a GitHub username.
// Returns empty string when unknown. Implementations should prefer
// graceful fallback (cache + best-effort fetch) over hard failures.
type GitHubUsernameResolver interface {
	GetGitHubUsername(ctx context.Context, clerkID string) (string, error)
}

// E2EUser is an explicitly configured local test identity.
type E2EUser struct {
	Token    string
	UserID   string
	Username string
	Email    string
}

// AuthOptions configures JWT verification. It mirrors the subset of the
// service's ClerkConfig that auth actually needs, so consumers are not
// coupled to the service config struct.
type AuthOptions struct {
	SecretKey     string
	E2EToken      string
	E2EUsers      map[string]E2EUser
	JWTLeewayMins int
}
