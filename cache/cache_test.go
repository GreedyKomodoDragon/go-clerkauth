package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/GreedyKomodoDragon/go-clerkauth/cache"
)

func newTestService(t *testing.T, apiKey string) (*cache.Service, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	opts := cache.Options{
		RedisClient: client,
		APIKey:      apiKey,
		CacheTTL:    30 * time.Minute,
		NotFoundTTL: 5 * time.Minute,
	}
	return cache.New(opts), mr
}

func TestGetGitHubUsername_CacheHit(t *testing.T) {
	svc, mr := newTestService(t, "")
	ctx := context.Background()

	require.NoError(t, mr.Set(cache.Key("user_cached"), "octocat"))
	mr.SetTTL(cache.Key("user_cached"), 30*time.Minute)

	v, err := svc.GetGitHubUsername(ctx, "user_cached")
	require.NoError(t, err)
	require.Equal(t, "octocat", v)
}

func TestGetGitHubUsername_NotFoundSentinel(t *testing.T) {
	svc, mr := newTestService(t, "")
	ctx := context.Background()

	require.NoError(t, mr.Set(cache.Key("user_nil"), cache.NotFoundSentinel))

	v, err := svc.GetGitHubUsername(ctx, "user_nil")
	require.NoError(t, err)
	require.Equal(t, "", v)
}

func TestGetGitHubUsername_NoAPIKeyDegrades(t *testing.T) {
	svc, _ := newTestService(t, "")
	v, err := svc.GetGitHubUsername(context.Background(), "missing-no-key")
	require.NoError(t, err)
	require.Equal(t, "", v)
}

func TestResolveMany_MixedHits(t *testing.T) {
	svc, mr := newTestService(t, "")
	ctx := context.Background()

	require.NoError(t, mr.Set(cache.Key("a"), "alice"))
	require.NoError(t, mr.Set(cache.Key("b"), cache.NotFoundSentinel))

	res, err := svc.ResolveMany(ctx, []string{"a", "b"}, 0)
	require.NoError(t, err)
	require.Equal(t, "alice", res["a"])
	require.Equal(t, "", res["b"])
}

func TestResolveMany_Empty(t *testing.T) {
	svc, _ := newTestService(t, "")
	res, err := svc.ResolveMany(context.Background(), nil, 0)
	require.NoError(t, err)
	require.Empty(t, res)
}
