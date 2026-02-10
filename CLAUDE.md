# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Traefik forward authentication middleware that uses GitHub OAuth for authentication and team-based authorization. Also provides `pkg/githuboauth` as a standalone, reusable Go library for adding GitHub OAuth to any Gin application.

## Multi-Module Repository

This is a multi-module Go repo with a `replace` directive in the root `go.mod`:
- **Root module** (`github.com/mxcd/github-fwd-auth`): The forward auth server application
- **Library module** (`github.com/mxcd/github-fwd-auth/pkg/githuboauth`): Standalone GitHub OAuth library with its own `go.mod`

When modifying the library, tests must be run from its directory (see below).

## Build & Test Commands

```bash
# Build the server
go build ./cmd/server/

# Run all library tests (the main test suite lives here)
cd pkg/githuboauth && go test -v -race -count=1 ./...

# Run a single test
cd pkg/githuboauth && go test -v -race -count=1 -run TestFunctionName ./...

# Build Docker image
docker build --platform=linux/amd64 -t github-fwd-auth .
```

There is no Makefile or linter configured. CI runs library tests then builds the main module.

## Architecture

```
Traefik → /ui-auth or /api-auth
  → rewriteRequestMiddleware (extracts X-Forwarded-* headers)
  → githuboauth middleware chain (OAuth routes, session check, API key fallback, team validation)
  → fwdAuthOK (optional JWT injection, returns 200)
```

**Entry point**: `cmd/server/main.go` — loads config via `github.com/mxcd/go-config` from env vars and `github-fwd-auth.env` file, initializes JWT signer (optional), creates OAuth handle, starts Gin server.

**Server** (`internal/server/`): Gin HTTP server. Unprotected routes: `/health`, `/JWKS`. Protected routes: `/ui-auth`, `/api-auth` which chain rewrite middleware → OAuth middleware → JWT injection.

**OAuth library** (`pkg/githuboauth/`): Core of the project. Handles OAuth flows (login, callback, logout with PKCE), encrypted cookie sessions (HMAC-SHA512 + AES-256), GitHub API calls (user info, team membership with pagination), API key authentication (timing-safe, pre-hashed), and team-based authorization. Two initialization modes: `Init()` for automatic middleware registration on a Gin engine, or `New()` + `GetMiddleware()` for manual route setup.

**JWT** (`pkg/jwt/`): RSA JWT signing/verification with JWKS endpoint. Token cache (LRU, 1min TTL) in the server layer avoids re-signing for the same user.

## Key Patterns

- **Logging**: `github.com/rs/zerolog` structured logging throughout. Use `log.Debug()`, `log.Error().Err(err).Msg(...)` etc.
- **Config**: All config via environment variables, loaded through `github.com/mxcd/go-config`. Sensitive fields are marked and excluded from logs.
- **Security annotations**: Security features are tagged with `F-XX` codes in comments (e.g., `F-02`, `F-11`).
- **Tests**: White-box tests in `package githuboauth`. Table-driven tests, `gin.CreateTestContext` for HTTP testing, mock HTTP servers for GitHub API. Test helpers in `testhelper_test.go`.
- **Error handling**: Check-and-return with zerolog context. `log.Fatal()` for startup failures in main.
