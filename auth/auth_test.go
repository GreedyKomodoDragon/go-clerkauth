package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GreedyKomodoDragon/go-clerkauth/auth"
	"github.com/GreedyKomodoDragon/go-clerkauth/userinfo"
)

type stubResolver struct{ username string }

func (s stubResolver) GetGitHubUsername(_ context.Context, _ string) (string, error) {
	return s.username, nil
}

func e2eOpts() userinfo.AuthOptions {
	return userinfo.AuthOptions{
		E2EToken: "e2e-secret",
		E2EUsers: map[string]userinfo.E2EUser{
			"u1": {Token: "tok-u1", UserID: "user_1", Username: "octocat", Email: "o@example.com"},
		},
	}
}

func TestVerify_E2EUser(t *testing.T) {
	info, err := auth.Verify(context.Background(), "tok-u1", e2eOpts(), nil)
	require.NoError(t, err)
	require.Equal(t, "user_1", info.UserID)
	require.Equal(t, "octocat", info.Username)
	require.Equal(t, userinfo.AuthTypeClerk, info.AuthType)
}

func TestVerify_E2EToken(t *testing.T) {
	info, err := auth.Verify(context.Background(), "e2e-secret", e2eOpts(), nil)
	require.NoError(t, err)
	require.Equal(t, "e2e-owner", info.UserID)
}

func TestVerify_InvalidToken(t *testing.T) {
	_, err := auth.Verify(context.Background(), "bogus", e2eOpts(), nil)
	require.Error(t, err)
}

func TestResolveUsername_Precedence(t *testing.T) {
	ctx := context.Background()
	cc := &auth.CustomClaims{Username: "fallback", PreferredUsername: "pref", Name: "name"}
	require.Equal(t, "fallback", auth.ResolveUsername(ctx, "u", cc, nil))

	cc.PreferredUsername = ""
	cc.Username = ""
	require.Equal(t, "pref", auth.ResolveUsername(ctx, "u", &auth.CustomClaims{PreferredUsername: "pref", Name: "n"}, nil))
	require.Equal(t, "", auth.ResolveUsername(ctx, "u", nil, nil))
	require.Equal(t, "fromapi", auth.ResolveUsername(ctx, "u", cc, stubResolver{"fromapi"}))
}

func TestExtractEmails_FiltersUnverified(t *testing.T) {
	cc := &auth.CustomClaims{
		Email:         "a@example.com",
		EmailVerified: true,
		Emails:        []auth.EmailEntry{{Email: "A@example.com", Verified: true}, {Email: "b@example.com"}},
	}
	emails := auth.ExtractEmails(cc)
	require.Equal(t, []string{"a@example.com"}, emails)
}

func TestMiddleware_JWTOnly_Unauthorized(t *testing.T) {
	m := auth.NewMiddleware(e2eOpts(), nil, nil)
	h := m.ClerkJWTOnly()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Header().Get("Www-Authenticate"), "Bearer realm=")
}

func TestMiddleware_JWTOnly_E2EOK(t *testing.T) {
	m := auth.NewMiddleware(e2eOpts(), nil, nil)
	h := m.ClerkJWTOnly()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := auth.GetUserInfo(r)
		require.True(t, ok)
		require.Equal(t, "user_1", info.UserID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer tok-u1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}
