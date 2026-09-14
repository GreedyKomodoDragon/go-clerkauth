package cache

import (
	"context"
	"sync"
)

// ResolveMany resolves many clerkIDs to GitHub usernames using Redis MGET
// for cache hits and concurrent Clerk fetches for misses. Returns a map
// from clerkID -> github username (empty string if not found).
func (s *Service) ResolveMany(ctx context.Context, clerkIDs []string, concurrency int) (map[string]string, error) {
	res := make(map[string]string, len(clerkIDs))
	if len(clerkIDs) == 0 {
		return res, nil
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}

	if concurrency <= 0 {
		concurrency = s.concurrency
	}
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 32 {
		concurrency = 32
	}

	client := s.redisClient
	keys := make([]string, len(clerkIDs))
	for i, id := range clerkIDs {
		keys[i] = Key(id)
	}

	misses := make([]string, 0)
	if client != nil {
		vals, err := client.MGet(ctx, keys...).Result()
		if err == nil {
			for i, v := range vals {
				id := clerkIDs[i]
				if v == nil {
					misses = append(misses, id)
					continue
				}
				str, _ := v.(string)
				if str == NotFoundSentinel {
					res[id] = ""
				} else {
					res[id] = str
				}
			}
		} else {
			misses = append(misses, clerkIDs...)
		}
	} else {
		misses = append(misses, clerkIDs...)
	}

	if len(misses) > 0 {
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, id := range misses {
			if err := ctx.Err(); err != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(clerkID string) {
				defer wg.Done()
				defer func() { <-sem }()
				gh, _ := s.GetGitHubUsername(ctx, clerkID)
				mu.Lock()
				res[clerkID] = gh
				mu.Unlock()
			}(id)
		}
		wg.Wait()
	}

	return res, nil
}
