# 📡 Sub Reverse Proxy / Clash Converter

A lightweight **Go-based reverse proxy + subscription converter** that fetches remote subscription links, decodes them, and converts them into **Clash-compatible YAML configs**.

Supports **full path passthrough reverse proxy mode** and runs as a simple web service.

---

## 🚀 Features

- 🌐 Reverse proxy subscription fetcher
- 🔁 Full path passthrough (no fixed routes)
- 📦 Base64 subscription decoding
- ⚙️ Converts VLESS nodes to Clash YAML
- 🧹 Automatically removes emoji characters from node names
- 🐳 Docker support
- 🚀 Auto build & publish to:
  - GitHub Container Registry (GHCR)
  - Docker Hub
- 🏷️ Versioned releases (`latest` + `v*` tags)

---

## 📦 Example Usage

### Run locally

```bash
export SUB_BASE="https://real3xuisub.tld"

go run main.go --serv
```

---

### Test request

```bash
curl http://localhost:8080/sub/token
```

This will internally fetch:

```
https://real3xuisub.tld/sub/token
```

---

## 🐳 Docker Usage

### Run container

```bash
docker run -d \
  -e SUB_BASE="https://real3xuisub.tld" \
  -p 8080:8080 \
  ghcr.io/mk990/sub2clash:latest
```

---

### Docker Hub

```bash
docker run -d \
  -e SUB_BASE="https://real3xuisub.tld" \
  -p 8080:8080 \
  mk990/sub2clash:latest
```

---

## ⚙️ Environment Variables

| Variable   | Description |
|------------|-------------|
| SUB_BASE   | Base subscription URL (required) |
| LISTEN     | Server port (default :8080) |

---

## 🧠 How it works

1. User calls:
   http://localhost:8080/<any/path>

2. Proxy forwards request to:
   SUB_BASE + /<any/path>

3. Response is:
- fetched
- base64 decoded
- parsed (VLESS supported)
- converted to Clash YAML

---

## 🐙 GitHub Actions

Automatically builds and pushes images:

- GHCR: ghcr.io/mk990/sub2clash:latest
- Docker Hub: mk990/sub2clash:latest

---

## 📜 License

MIT License
