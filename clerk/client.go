// Package clerk verifies Clerk session tokens and resolves verified Clerk profiles.
package clerk

import (
	"context"
	"errors"
	"strings"
	"time"

	clerkapi "github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/jwks"
	"github.com/clerk/clerk-sdk-go/v2/jwt"
	"github.com/clerk/clerk-sdk-go/v2/user"
)

// Identity is the verified Clerk identity a service can persist locally.
type Identity struct {
	Subject, Email, Name, Avatar string
}

// Client validates tokens against allowed browser origins and resolves profiles.
type Client struct {
	parties map[string]struct{}
	leeway  time.Duration
	jwks    *jwks.Client
	users   *user.Client
}

// NewClient constructs a Clerk client with explicit authorized frontend origins.
func NewClient(secretKey string, parties []string, leeway time.Duration) (*Client, error) {
	if secretKey == "" {
		return nil, errors.New("Clerk secret key is required")
	}
	allowed := make(map[string]struct{}, len(parties))
	for _, party := range parties {
		if party = strings.TrimSpace(party); party != "" {
			allowed[party] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("at least one Clerk authorized party is required")
	}
	config := &clerkapi.ClientConfig{BackendConfig: clerkapi.BackendConfig{Key: &secretKey}}
	return &Client{parties: allowed, leeway: leeway, jwks: jwks.NewClient(config), users: user.NewClient(config)}, nil
}

// VerifyToken validates a Clerk JWT without making an upstream profile request.
func (c *Client) VerifyToken(ctx context.Context, token string) (string, error) {
	claims, err := jwt.Verify(ctx, &jwt.VerifyParams{Token: token, JWKSClient: c.jwks, Leeway: c.leeway, AuthorizedPartyHandler: func(azp string) bool { _, ok := c.parties[azp]; return ok }})
	if err != nil || claims.Subject == "" {
		return "", errors.New("invalid Clerk token")
	}
	return claims.Subject, nil
}

// Resolve loads the current verified Clerk profile for a Clerk subject.
func (c *Client) Resolve(ctx context.Context, subject string) (Identity, error) {
	person, err := c.users.Get(ctx, subject)
	if err != nil || person.PrimaryEmailAddressID == nil {
		return Identity{}, errors.New("could not resolve Clerk user")
	}
	var email string
	for _, address := range person.EmailAddresses {
		if address.ID == *person.PrimaryEmailAddressID && address.Verification != nil && address.Verification.Status == "verified" {
			email = address.EmailAddress
			break
		}
	}
	if email == "" {
		return Identity{}, errors.New("Clerk primary email is not verified")
	}
	name := strings.TrimSpace(strings.TrimSpace(value(person.FirstName)) + " " + strings.TrimSpace(value(person.LastName)))
	return Identity{Subject: subject, Email: email, Name: name, Avatar: value(person.ImageURL)}, nil
}

// Verify validates a Clerk token and resolves its verified profile.
func (c *Client) Verify(ctx context.Context, token string) (Identity, error) {
	subject, err := c.VerifyToken(ctx, token)
	if err != nil {
		return Identity{}, err
	}
	return c.Resolve(ctx, subject)
}

// value dereferences optional Clerk text fields.
func value(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
