---
title: Server Configuration
description: Configure and run the QPKI Enterprise REST API server
---

## Running the Server

```bash
# Start with default settings
qpki-server

# Custom port and host
qpki-server --addr 0.0.0.0:8443

# With TLS
qpki-server --tls-cert server.crt --tls-key server.key
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QPKI_ADDR` | Listen address | `localhost:8443` |
| `QPKI_DATA_DIR` | Data directory | `./data` |
| `QPKI_LOG_LEVEL` | Log level | `info` |

## Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Basic health check |
| `GET /ready` | Readiness probe (checks dependencies) |

## CORS Configuration

The server enables CORS by default for development. Configure allowed origins in production:

```bash
qpki-server --cors-origins "https://app.example.com"
```
