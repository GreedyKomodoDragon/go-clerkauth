// Package auth ports Clerk JWT verification and HTTP middleware out of the
// service's internal/middleware package.
//
// Verify is a pure function (token + opts + optional username resolver) so it
// is testable without HTTP. The Middleware constructors add the HTTP layer
// plus an injectable deletion-block hook (which stays app-specific).
package auth

import (
	"context"
	"strings"

	"huxim/libs/clerkauth/userinfo"
)

type ExternalAccount struct {
	Provider string `json:"provider"`
	Username string `json:"username"`
}

type PublicMetadata struct {
	Emails         []string `json:"emails"`
	GithubUsername string   `json:"github_username"`
}

type EmailEntry struct {
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
	EmailVerified bool   `json:"email_verified"`
}

// CustomClaims mirrors the custom session claims the service reads from Clerk JWTs.
type CustomClaims struct {
	ExternalAccounts  []ExternalAccount `json:"external_accounts"`
	PublicMetadata    PublicMetadata    `json:"public_metadata"`
	Emails            []EmailEntry      `json:"emails"`
	EmailAddresses    []EmailEntry      `json:"email_addresses"`
	Email             string            `json:"email"`
	EmailVerified     bool              `json:"email_verified"`
	Username          string            `json:"username"`
	PreferredUsername string            `json:"preferred_username"`
	Name              string            `json:"name"`
}

// ResolveUsername applies the service's precedence: JWT external_accounts
// github entry, then public_metadata github_username, then the Clerk API
// resolver fallback, then username / preferred_username / name claims.
func ResolveUsername(ctx context.Context, clerkID string, cc *CustomClaims, resolver userinfo.GitHubUsernameResolver) string {
	if cc != nil {
		for _, ea := range cc.ExternalAccounts {
			if strings.EqualFold(ea.Provider, "github") && ea.Username != "" {
				return ea.Username
			}
		}
		if cc.PublicMetadata.GithubUsername != "" {
			return cc.PublicMetadata.GithubUsername
		}
	}

	if resolver != nil {
		if gh, err := resolver.GetGitHubUsername(ctx, clerkID); err == nil && gh != "" {
			return gh
		}
	}

	if cc == nil {
		return ""
	}
	if cc.Username != "" {
		return cc.Username
	}
	if cc.PreferredUsername != "" {
		return cc.PreferredUsername
	}
	return cc.Name
}

// ExtractEmails returns deduplicated, lowercased verified emails from claims.
func ExtractEmails(cc *CustomClaims) []string {
	if cc == nil {
		return []string{}
	}
	var emails []string
	if cc.Email != "" && cc.EmailVerified {
		emails = append(emails, strings.ToLower(cc.Email))
	}
	for _, e := range cc.Emails {
		if e.Email != "" && (e.Verified || e.EmailVerified) {
			emails = append(emails, strings.ToLower(e.Email))
		}
	}
	for _, e := range cc.EmailAddresses {
		if e.Email != "" && (e.Verified || e.EmailVerified) {
			emails = append(emails, strings.ToLower(e.Email))
		}
	}
	if len(emails) == 0 && len(cc.PublicMetadata.Emails) > 0 {
		for _, s := range cc.PublicMetadata.Emails {
			if s != "" {
				emails = append(emails, strings.ToLower(s))
			}
		}
	}
	uniq := map[string]struct{}{}
	res := make([]string, 0, len(emails))
	for _, e := range emails {
		if e == "" {
			continue
		}
		if _, ok := uniq[e]; !ok {
			uniq[e] = struct{}{}
			res = append(res, e)
		}
	}
	return res
}
