# go-clerkauth

Shared Clerk authentication helpers for Go services.

It provides Clerk JWT verification and `net/http` middleware, a Redis-backed
Clerk-to-GitHub username resolver, and shared request identity types.

## Install

The module uses the import path `github.com/GreedyKomodoDragon/go-clerkauth`:

```sh
go get github.com/GreedyKomodoDragon/go-clerkauth@v0.1.0
```

## Use Clerk middleware

```go
opts := userinfo.AuthOptions{
	SecretKey:     os.Getenv("CLERK_SECRET_KEY"),
	JWTLeewayMins: 1,
}

resolver := cache.New(cache.Options{
	RedisClient:  redisClient,
	APIKey:       os.Getenv("CLERK_SECRET_KEY"),
	CacheTTL:     time.Hour,
	NotFoundTTL:  5 * time.Minute,
})

middleware := auth.NewMiddleware(opts, resolver, nil)
handler := middleware.ClerkJWTOnly()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.GetUserInfo(r)
	fmt.Fprintln(w, user.Username)
}))
```

`ClerkJWTOnly` accepts Bearer Clerk JWTs. `ClerkAuth` also accepts Basic
registry credentials through a caller-supplied verifier. Both attach a
`userinfo.UserInfo` to the request context.

## Packages

- `auth` verifies Clerk JWTs, resolves usernames and supplies HTTP middleware.
- `cache` resolves Clerk IDs to GitHub usernames through Redis and the Clerk API.
- `userinfo` contains the shared `UserInfo`, options and resolver contract.

## Test

```sh
go test ./...
```
