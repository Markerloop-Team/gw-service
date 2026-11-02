# gw-service

The API gateway of the Markerloop platform: the single public entry point that authenticates requests, enforces
RBAC and workspace boundaries, and reverse-proxies to the backend services.

Markerloop is a shared backend (users, auth, files, collections, notifications, i18n) plus a page builder that an AI
agent drives through MCP. Every public request — from the admin UI, from customer sites and from the MCP server —
passes through this gateway.

## Responsibilities

- **Routing**: one Gin router fronting `auth`, `user`, `notification`, `dictionary`, `collections`, `files`, `pages`
  and the Telegram bot service. Route table and per-route permission requirements live in
  `internal/config/routes.go` (126 route rules).
- **Authentication**: verifies RS256 access tokens with the public key only — the gateway never signs tokens.
- **Authorization (RBAC)**: for routes that require a permission (e.g. `users:read:all`, `roles:assign:permission`)
  the gateway asks `user-service` (`/internal/users/{id}/check-permission`) and caches results in Redis.
- **Workspace scoping**: on workspace routes it resolves the actor's role in the workspace, then forwards trusted
  `X-Scope-*` headers downstream. Client-supplied identity headers (e.g. `X-User-ID`) are stripped before proxying,
  so services can trust what the gateway sends.
- **Token boundaries**:
  - tokens with an `aud` claim (MCP agent tokens) are rejected on session routes;
  - workspace tokens are confined to their own workspace;
  - optional strict mode (`SCOPE_REQUIRE_WORKSPACE_TOKEN=true`) requires workspace tokens on workspace-scoped routes.
- **Membership revocation**: when a member is removed or a workspace is deleted, markers in Redis invalidate cached
  roles immediately instead of waiting for TTLs.
- **Public data plane**: anonymous `/api/v1/data/*` and public page reads are proxied with their own CORS policy.
- **Docs aggregation**: `/api/docs/<service>/swagger/*` proxies each service's Swagger UI.
- **Health fan-out**: `/api/health` and per-service health checks.

## Route groups

All under `/api/v1`: `/auth`, `/oauth`, `/users`, `/policy-acceptances`, `/roles`, `/permissions`,
`/external-accounts`, `/notifications` (service key), `/dictionary` (public), `/telegram`, `/workspaces`, `/invites`,
`/collections`, `/records`, `/files`, `/pages`, `/data`. OAuth metadata is exposed at
`/api/.well-known/oauth-authorization-server`.

## Architecture notes

- **Middleware** (`internal/middleware`): shared recovery / request-id / logging / CORS from `go-sdk`, plus
  gateway-specific pieces — audience guard, permission check, workspace scope resolution, workspace-token boundary,
  membership revocation and the split CORS policy for the public data plane.
- **Proxy**: `internal/proxy` implements the reverse proxy with timeouts, header hygiene and log redaction
  (tokens and personal data are not written to logs — covered by tests).
- **State**: stateless apart from the optional Redis cache; safe to run multiple replicas.
- No message broker; upstream calls are plain HTTP inside the cluster.

## Running locally

```bash
cp .env.example .env        # upstream URLs, JWT_PUBLIC_KEY, SERVICE_KEY
docker run -d -p 6379:6379 redis:7   # optional permission cache
go run ./cmd/server
curl localhost:8080/api/health
```

Live reload: `air` (config in `.air.toml`).

Docker:

```bash
docker build --build-arg DEPLOY_TOKEN_USERNAME=<user> --build-arg DEPLOY_TOKEN_PASSWORD=<token> -t gw-service .
docker run -p 8080:8080 --env-file .env gw-service
```

## Tests

```bash
go test ./...
```

About 40 test files, most of them **contract tests** in `internal/routes` that pin the gateway's behaviour per route
group: which token kinds are accepted, which headers reach the upstream, which permission is enforced, CORS on the
data plane, billing and invite routes, workspace-token exchange and boundaries. Redis is replaced with `miniredis`;
no external services are needed.

## Notes for reviewers

- Go module name is `gateway-service`. Code comments are largely in Russian.
- The shared library is imported as `gitlab.com/markerloop/go-sdk` (private GitLab) and is published as
  [Markerloop-Team/go-sdk](https://github.com/Markerloop-Team/go-sdk); to build outside our CI, clone it and add
  `replace gitlab.com/markerloop/go-sdk => ../go-sdk` to `go.mod`.
- Snapshot without git history. Ticket ids in comments refer to our internal tracker.

## Part of Markerloop

Markerloop is a shared backend and site builder with an AI agent working through MCP.
Website: [markerloop.com](https://markerloop.com) · Code: [github.com/Markerloop-Team](https://github.com/Markerloop-Team)

---

Source published for review. © Markerloop. All rights reserved.
