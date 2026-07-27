# Web Security Platform (WSP) v1

On-premises web security suite: explicit HTTP/HTTPS proxy with TLS interception, ordered policy, RBI, inline CASB, ClamAV anti-malware, and a management plane.

> **Status:** repository scaffold (module, config, Compose, migrations). Runtime features land in subsequent tasks.

## Quick start (Docker Compose, Linux)

```bash
cd deploy
cp env.example .env
# set WSP_DATA_KEY to a 32-byte secret (e.g. openssl rand -base64 32)
docker compose up -d --build
```

| Listener   | Default | Role                          |
|------------|---------|-------------------------------|
| Proxy      | `:8080` | Explicit HTTP/HTTPS proxy     |
| Management | `:3000` | REST API + admin SPA          |

## Development

```bash
go test ./internal/config/...
go build -o bin/wsp ./cmd/wsp
./bin/wsp --version   # 0.1.0
```

Module path: `github.com/wsp-security/wsp`

## Layout

- `cmd/wsp` — single binary entrypoint
- `internal/config` — env bootstrap
- `migrations` — ordered SQL (PostgreSQL 16)
- `deploy` — Dockerfile + Compose
- `web` — admin UI (placeholder; React app later)

## License

Open source — license file TBD.
