package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/clerk/clerk-sdk-go/v2/jwt"

	"github.com/GreedyKomodoDragon/go-clerkauth/userinfo"
)

// Verify validates a Clerk JWT (or E2E bypass token) and builds a UserInfo.
// E2E bypass is checked first so tests never touch JWKS.
func Verify(ctx context.Context, token string, opts userinfo.AuthOptions, resolver userinfo.GitHubUsernameResolver) (*userinfo.UserInfo, error) {
	for _, user := range opts.E2EUsers {
		if user.Token == "" || token != user.Token {
			continue
		}
		emails := []string{}
		if user.Email != "" {
			emails = []string{user.Email}
		}
		return &userinfo.UserInfo{
			UserID: user.UserID, Username: user.Username,
			Email: user.Email, Emails: emails, AuthType: userinfo.AuthTypeClerk,
		}, nil
	}
	if opts.E2EToken != "" && token == opts.E2EToken {
		return &userinfo.UserInfo{
			UserID: "e2e-owner", Username: "e2e-owner",
			Email: "e2e@example.test", Emails: []string{"e2e@example.test"},
			AuthType: userinfo.AuthTypeClerk,
		}, nil
	}
	return VerifyJWT(ctx, token, opts.JWTLeewayMins, resolver)
}

// VerifyJWT validates a Clerk JWT against JWKS (no E2E bypass) and builds a
// UserInfo. Leeway in minutes accommodates clock drift between client, Clerk
// servers, and backend.
func VerifyJWT(ctx context.Context, token string, leewayMins int, resolver userinfo.GitHubUsernameResolver) (*userinfo.UserInfo, error) {
	leeway := time.Duration(leewayMins) * time.Minute
	claims, err := jwt.Verify(ctx, &jwt.VerifyParams{
		Token:                   token,
		Leeway:                  leeway,
		CustomClaimsConstructor: func(_ context.Context) any { return &CustomClaims{} },
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("missing subject claim")
	}

	var cc *CustomClaims
	if claims.Custom != nil {
		if typed, ok := claims.Custom.(*CustomClaims); ok {
			cc = typed
		}
	}

	username := ResolveUsername(ctx, claims.Subject, cc, resolver)
	info := &userinfo.UserInfo{
		UserID: claims.Subject, Username: username,
		AuthType: userinfo.AuthTypeClerk, Emails: []string{},
	}
	if emails := ExtractEmails(cc); len(emails) > 0 {
		info.Emails = emails
		info.Email = emails[0]
	}
	return info, nil
}
