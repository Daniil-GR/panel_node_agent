# Vetka VPN node-agent notes

This project is used as a node-side agent. The central Vetka Backend owns end-user subscriptions such as:

```text
https://sub.vetka.tech/sub/<token>
```

The node-agent only manages local Naive/Mieru users, applies Caddy/Mieru configs, and returns node data to the Backend.

## Internal API

Authorization:

```http
Authorization: Bearer <NODE_API_KEY>
```

`backendAllowedIps` protects every `/internal/*` endpoint. By default it is `["127.0.0.1"]`. If the list is empty, all Backend IPs are rejected unless `allowAnyBackendIp=true` is explicitly enabled.

Endpoints:

```text
GET    /internal/health
GET    /internal/version
GET    /internal/settings
PATCH  /internal/settings
GET    /internal/node/info
GET    /internal/node/sessions
GET    /internal/users
GET    /internal/users/:id
POST   /internal/users
PATCH  /internal/users/:id
DELETE /internal/users/:id
POST   /internal/users/:id/enable
POST   /internal/users/:id/disable
GET    /internal/users/:id/config/naive
GET    /internal/users/:id/config/mieru
GET    /internal/users/:id/config/universal
GET    /internal/users/:id/sessions
POST   /internal/users/:id/reset-sessions
POST   /internal/users/:id/rotate-subscription-token
```

Create user example:

```bash
curl -X POST http://127.0.0.1:3000/internal/users \
  -H "Authorization: Bearer $NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username":"u_123456","password":"random_password","protocols":["naive"],"quotaGb":0,"expiresAt":"2026-12-31T23:59:59Z","enabled":true}'
```

## Caddy/Naive

Every Caddyfile rebuild writes `/etc/caddy-naive/Caddyfile` atomically, sets:

```bash
chown root:caddy /etc/caddy-naive/Caddyfile
chmod 640 /etc/caddy-naive/Caddyfile
```

The directory is kept group-traversable for `caddy`:

```bash
chown root:caddy /etc/caddy-naive
chmod 750 /etc/caddy-naive
```

After write, the panel validates:

```bash
/usr/local/bin/caddy-naive validate --config /etc/caddy-naive/Caddyfile --adapter caddyfile
```

Only after successful validation does it reload or restart `caddy-naive`. If that fails, the API returns `{ "ok": false, "error": "..." }`.

## Clean install

```bash
sudo bash install.sh \
  --non-interactive \
  --domain node-1.example.com \
  --email admin@example.com \
  --naive-port 443 \
  --lang en
```

Then read `/etc/rixxx-panel/config.json` for `nodeApiKey` and set `backendAllowedIps` to the central Backend IP.

## Node API key

The installer writes `nodeApiKey` to `/etc/rixxx-panel/config.json`. In the web UI, open **Server Settings** and use the **Vetka Node API** card to view and copy the key. The same card can regenerate the key; after regeneration, update the central Backend immediately because old clients stop working.

Add the Vetka Backend public IP in the same UI card under `backendAllowedIps`, one IP per line, then save. The setting is written to `/etc/rixxx-panel/config.json` and takes effect without reinstalling.

Do not expose the web UI publicly. Keep the panel bound to `127.0.0.1` and administer it through SSH tunneling or another private admin channel.

## Subscriptions

Each user has a random `subscriptionToken`. The token is returned in admin and internal user payloads and is used for local node subscription tests:

```text
https://<domain>/sub/<subscriptionToken>?format=json
```

If `subscriptionBaseUrl` is empty, the node builds local subscription links as `https://<domain>/sub`. This local endpoint is for node smoke tests and emergency inspection. Production end-user subscriptions remain owned by the central Vetka Backend:

```text
https://sub.vetka.tech/sub/<token>
```

The public node subscription path is the only panel route exposed through `caddy-naive`. The Caddy site block proxies `/sub/*` to the local Express listener on `127.0.0.1:3000`; all other ordinary browser requests still fall back to the fake-site, and Naive CONNECT traffic continues through `forward_proxy`.

The Backend will aggregate several nodes and protocols into one final sing-box subscription. User abuse-control in the short term should live at the Backend/subscription layer where the Backend sees the global token and request context.

Rotate a node token when needed:

```bash
curl -X POST http://127.0.0.1:3000/internal/users/<id>/rotate-subscription-token \
  -H "Authorization: Bearer $NODE_API_KEY"
```

## Active IP tracking

Naive is served through a shared Caddy forwardproxy listener. Node-level IP monitoring still uses Caddy `access.log`, but per-user Naive sessions come only from the Vetka forwardproxy `auth_audit_log` JSONL file configured by `authAuditLogPath`. The node-agent does not parse `Proxy-Authorization`, does not enable credential logging, and does not read passwords or raw Basic credentials.

Node-level IP monitoring is available:

```bash
curl -H "Authorization: Bearer $NODE_API_KEY" \
  http://127.0.0.1:3000/internal/node/sessions
```

Per-user IP monitoring is available when `authAuditLogPath` points to the patched forwardproxy audit log:

```bash
curl -H "Authorization: Bearer $NODE_API_KEY" \
  http://127.0.0.1:3000/internal/users/<id>/sessions
```

If the audit log is not configured or not present, session endpoints return `trackingAvailable: false` with reason `auth audit log not configured`.

## Smoke tests

```bash
curl -I https://<domain>
```

```bash
curl -v \
  -x https://<domain>:443 \
  --proxy-user '<username>:<password>' \
  https://www.gstatic.com/generate_204 \
  -o /dev/null \
  -w '\ncode:%{http_code} time:%{time_total}s\n'
```

```bash
ls -la /etc/caddy-naive/Caddyfile
journalctl -u caddy-naive -n 100 --no-pager | grep -i 'permission denied' || true
```

```bash
curl -H "Authorization: Bearer $NODE_API_KEY" \
  http://127.0.0.1:3000/internal/health
```

```bash
curl -H "Authorization: Bearer $NODE_API_KEY" \
  http://127.0.0.1:3000/internal/version
```

Backend request example:

```bash
curl -X PATCH http://127.0.0.1:3000/internal/settings \
  -H "Authorization: Bearer $NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"backendAllowedIps":["127.0.0.1","203.0.113.20"],"sessionTtlMinutes":10,"authAuditLogPath":"/var/log/caddy-naive/auth-audit.log","maxUniqueIpsPerUser":5,"enforceIpLimit":false}'
```

```bash
curl -H "Authorization: Bearer $NODE_API_KEY" \
  http://127.0.0.1:3000/internal/node/sessions
```

Local node subscription smoke test:

```bash
curl -I "https://<domain>/sub/<subscriptionToken>?format=json"
curl -s "https://<domain>/sub/<subscriptionToken>?format=json" | jq .
curl -I https://<domain>/
```

```bash
curl -X POST http://127.0.0.1:3000/internal/users \
  -H "Authorization: Bearer $NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username":"test_api","password":"testpass123","protocols":["naive"],"quotaGb":0,"enabled":true}'
```

## Architecture

The Express panel stores users, subscription tokens, service config, and session reset watermarks in SQLite. User changes rebuild the Caddyfile and Mieru state file, validate Caddy, and then apply services. Node-level Naive IP activity is summarized from `/var/log/caddy-naive/access.log`; per-user Naive IP sessions are summarized from `/var/log/caddy-naive/auth-audit.log` when configured.
