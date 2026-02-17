---
title: "API Server"
description: "Configuration and deployment of the QPKI REST API server"
---

# API Server

The `qpki serve` command starts an HTTP server exposing the REST API and RFC responders.

## Quick Start

```bash
# Start with all services
qpki serve --port 8443 --ca-dir ./pki

# Verify the server
curl http://localhost:8443/health
```

## Command Line Options

### Ports

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8443 | Port for all services |
| `--api-port` | - | Dedicated port for REST API (overrides `--port`) |
| `--ocsp-port` | - | Dedicated port for OCSP responder |
| `--tsa-port` | - | Dedicated port for TSA responder |
| `--host` | `0.0.0.0` | Network interface to bind |

### Configuration

| Flag | Description |
|------|-------------|
| `--ca-dir` | Directory containing CAs |
| `--services` | Services to enable (see below) |
| `--tls-cert` | Server TLS certificate |
| `--tls-key` | TLS private key |

### Available Services

| Service | Description | Endpoints |
|---------|-------------|-----------|
| `api` | Complete REST API | `/api/v1/*` |
| `ocsp` | RFC 6960 OCSP responder | `/ocsp` |
| `tsa` | RFC 3161 TSA responder | `/tsa` |
| `all` | All services (default) | All |

## Environment Variables

All options can be configured via environment variables:

| Variable | Equivalent Flag |
|----------|-----------------|
| `QPKI_PORT` | `--port` |
| `QPKI_API_PORT` | `--api-port` |
| `QPKI_OCSP_PORT` | `--ocsp-port` |
| `QPKI_TSA_PORT` | `--tsa-port` |
| `QPKI_SERVICES` | `--services` |
| `QPKI_CA_DIR` | `--ca-dir` |
| `QPKI_TLS_CERT` | `--tls-cert` |
| `QPKI_TLS_KEY` | `--tls-key` |

Command line flags take precedence over environment variables.

## Configuration Examples

### Single Port (recommended for development)

```bash
qpki serve --port 8443 --ca-dir ./pki
```

All services are accessible on the same port:
- `http://localhost:8443/api/v1/*` - REST API
- `http://localhost:8443/ocsp` - OCSP responder
- `http://localhost:8443/tsa` - TSA responder
- `http://localhost:8443/health` - Health check

### Separate Ports (recommended for production)

```bash
qpki serve \
  --api-port 8443 \
  --ocsp-port 8080 \
  --tsa-port 8081 \
  --ca-dir ./pki
```

This allows you to:
- Apply different firewall rules per service
- Configure separate reverse proxies
- Monitor each service independently

### Selective Services

```bash
# REST API only
qpki serve --port 8443 --services api

# OCSP and TSA only (for dedicated responders)
qpki serve --port 8080 --services ocsp,tsa

# Via environment variable
QPKI_SERVICES=ocsp,tsa qpki serve --port 8080
```

### With TLS

```bash
qpki serve \
  --port 8443 \
  --tls-cert /etc/qpki/server.crt \
  --tls-key /etc/qpki/server.key \
  --ca-dir /var/lib/qpki
```

The server will listen on HTTPS.

## Deployment

### Systemd

```ini
# /etc/systemd/system/qpki-api.service
[Unit]
Description=QPKI REST API Server
After=network.target

[Service]
Type=simple
User=qpki
Group=qpki
Environment=QPKI_PORT=8443
Environment=QPKI_CA_DIR=/var/lib/qpki
Environment=QPKI_SERVICES=all
ExecStart=/usr/local/bin/qpki serve
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable qpki-api
sudo systemctl start qpki-api
```

### Docker

```dockerfile
FROM alpine:3.19
COPY qpki /usr/local/bin/
EXPOSE 8443
ENTRYPOINT ["qpki", "serve"]
CMD ["--port", "8443", "--ca-dir", "/data"]
```

```bash
docker run -d \
  -p 8443:8443 \
  -v ./pki:/data \
  qpki-server
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qpki-api
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: qpki
        image: qpki:latest
        ports:
        - containerPort: 8443
        env:
        - name: QPKI_PORT
          value: "8443"
        - name: QPKI_CA_DIR
          value: "/data"
        volumeMounts:
        - name: pki-data
          mountPath: /data
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
        readinessProbe:
          httpGet:
            path: /ready
            port: 8443
```

## System Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (liveness) |
| `/ready` | GET | Readiness check |
| `/api/openapi.yaml` | GET | OpenAPI 3.1 specification |

### Health Check

```bash
curl http://localhost:8443/health
```

```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

### Readiness Check

```bash
curl http://localhost:8443/ready
```

```json
{
  "ready": true,
  "services": ["api", "ocsp", "tsa"]
}
```

## Logging

The server writes logs to stdout in structured format:

```
2024-01-15T10:30:45Z INFO  Starting QPKI server version=1.0.0
2024-01-15T10:30:45Z INFO  Services enabled services=[api,ocsp,tsa]
2024-01-15T10:30:45Z INFO  Listening on :8443
2024-01-15T10:30:46Z INFO  Request method=POST path=/api/v1/ca/init status=201 duration=45ms
```

## Security

### Recommendations

1. **TLS required** in production
2. **Firewall**: Restrict access to API ports
3. **Reverse proxy**: Nginx/Caddy in front for rate limiting and auth
4. **Audit**: Enable `--audit-log` for traceability

### Reverse Proxy (Nginx)

```nginx
upstream qpki {
    server 127.0.0.1:8443;
}

server {
    listen 443 ssl;
    server_name pki.example.com;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    location /api/ {
        proxy_pass http://qpki;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Request-ID $request_id;
    }

    location /ocsp {
        proxy_pass http://qpki;
    }

    location /tsa {
        proxy_pass http://qpki;
    }
}
```

## Next Steps

- [Endpoint Reference](/qpki/api/endpoints) - Complete API documentation
- [Examples](/qpki/api/examples) - Usage scenarios
