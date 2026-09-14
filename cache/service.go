// Package cache resolves Clerk user IDs to GitHub usernames with a Redis
// read-through cache and a best-effort Clerk API fallback.
//
// It depends only on go-redis, prometheus client, and the userinfo contract —
// never on service internals (worker.Runtime, internal/logger, internal/config).
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"

	"github.com/GreedyKomodoDragon/go-clerkauth/userinfo"
)

// NotFoundSentinel marks a known-missing username in Redis.
const NotFoundSentinel = "__nil__"

// Key returns the Redis key for a Clerk ID.
func Key(clerkID string) string { return fmt.Sprintf("clerk:gh:%s", clerkID) }

// Options configures the Service. Zero values are safe: nil Redis client
// means fetch-through without caching, nil HTTPClient uses a 10s default,
// nil Registry disables metrics, nil Logger discards logs.
type Options struct {
	RedisClient  *redis.Client
	APIKey       string
	HTTPClient   *http.Client
	CacheTTL     time.Duration
	NotFoundTTL  time.Duration
	Registry     prometheus.Registerer
	Logger       *slog.Logger
	ConcurrLimit int
}

// Service is a Redis-backed Clerk → GitHub username resolver.
type Service struct {
	redisClient *redis.Client
	apiKey      string
	httpClient  *http.Client
	cacheTTL    time.Duration
	notFoundTTL time.Duration
	concurrency int
	logger      *slog.Logger

	metricHit   prometheus.Counter
	metricMiss  prometheus.Counter
	metricFetch prometheus.Counter
}

// Compile-time check: Service satisfies the shared resolver contract.
var _ userinfo.GitHubUsernameResolver = (*Service)(nil)

// New builds a Service from explicit dependencies.
func New(opts Options) *Service {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	concurrency := opts.ConcurrLimit
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 32 {
		concurrency = 32
	}
	s := &Service{
		redisClient: opts.RedisClient,
		apiKey:      opts.APIKey,
		httpClient:  httpClient,
		cacheTTL:    opts.CacheTTL,
		notFoundTTL: opts.NotFoundTTL,
		concurrency: concurrency,
		logger:      logger,
	}
	if opts.Registry != nil {
		s.metricHit = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "clerk_cache_hits_total",
			Help: "Total clerk cache hits",
		})
		s.metricMiss = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "clerk_cache_misses_total",
			Help: "Total clerk cache misses",
		})
		s.metricFetch = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "clerk_fetches_total",
			Help: "Total Clerk API fetches",
		})
		opts.Registry.MustRegister(s.metricHit, s.metricMiss, s.metricFetch)
	}
	return s
}

// GetGitHubUsername resolves a clerkID to a GitHub username, using Redis
// cache when available. Returns empty string when not found. Clerk API or
// cache failures degrade to ("", nil) so callers can fall back to claims.
func (s *Service) GetGitHubUsername(ctx context.Context, clerkID string) (string, error) {
	key := Key(clerkID)

	client := s.redisClient
	if client != nil {
		if v, err := client.Get(ctx, key).Result(); err == nil {
			if s.metricHit != nil {
				s.metricHit.Inc()
			}
			if v == NotFoundSentinel {
				return "", nil
			}
			return v, nil
		}
		if s.metricMiss != nil {
			s.metricMiss.Inc()
		}
	} else if s.metricMiss != nil {
		s.metricMiss.Inc()
	}

	if s.metricFetch != nil {
		s.metricFetch.Inc()
	}
	username, err := s.fetchFromClerk(ctx, clerkID)
	if err != nil {
		s.logger.Warn("clerk: fetch failed", "error", err)
		return "", nil
	}

	if client != nil {
		val := username
		ttl := s.cacheTTL
		if username == "" {
			val = NotFoundSentinel
			ttl = s.notFoundTTL
		}
		if err := client.Set(ctx, key, val, ttl).Err(); err != nil {
			s.logger.Warn("clerk: failed to set cache", "error", err)
		}
	}
	return username, nil
}

// fetchFromClerk performs the Clerk user lookup and extracts the GitHub
// username. Returns ("", nil) for unknown users; returns an error only for
// transport/parse failures so the caller can decide fallback behavior.
func (s *Service) fetchFromClerk(ctx context.Context, clerkID string) (string, error) {
	if s.apiKey == "" {
		return "", nil
	}
	url := fmt.Sprintf("https://api.clerk.com/v1/users/%s", clerkID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	var data struct {
		ExternalAccounts []struct {
			Provider string `json:"provider"`
			Username string `json:"username"`
		} `json:"external_accounts"`
		Username       string                 `json:"username"`
		PublicMetadata map[string]interface{} `json:"public_metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	for _, ea := range data.ExternalAccounts {
		if strings.EqualFold(ea.Provider, "github") && ea.Username != "" {
			return ea.Username, nil
		}
	}
	if data.Username != "" {
		return data.Username, nil
	}
	if v, ok := data.PublicMetadata["github_username"]; ok {
		if str, ok := v.(string); ok && str != "" {
			return str, nil
		}
	}
	return "", nil
}
