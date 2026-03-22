# Cowrie Map and WordPress Web Honeypot

Lightweight local web app for ingesting Cowrie SSH/Telnet logs, serving a fake WordPress-style low-interaction web honeypot, enriching source IPs with local MaxMind GeoLite2 databases, storing everything in SQLite, and rendering an interactive Leaflet map.

## Project Layout

```text
.
├── app
│   ├── Dockerfile
│   ├── honeypot_assets
│   ├── main.py
│   ├── requirements.txt
│   └── templates
├── compose.yml
├── data
├── geoip
├── README.md
└── web
    ├── app.js
    ├── index.html
    └── style.css
```

## What It Does

- Reads Cowrie JSON lines from `/opt/honeypot/cowrie/cowrie-var/log/cowrie/cowrie.json`
- Tracks `cowrie.session.connect`, `cowrie.login.failed`, `cowrie.login.success`, and `cowrie.command.input`
- Serves a fake WordPress-style surface at `/`, `/wp-login.php`, `/wp-admin`, `/xmlrpc.php`, `/wp-json`, `/readme.html`, `/license.txt`, `/robots.txt`, and common probe paths
- Logs WordPress-like web probes, login attempts, headers, user-agents, paths, query strings, and response metadata
- Enriches source IPs with local `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
- Stores parsed events in SQLite at `./data/cowrie_map.db`
- Prevents duplicate ingestion with a unique SHA-256 hash per log line
- Polls the Cowrie log every 15 seconds and only processes new complete lines
- Exposes `/health`, `/api/events`, `/api/summary`, and `/api/geojson` on a private dashboard port
- Keeps the fake WordPress site and the dashboard on separate ports
- Keeps the web honeypot deterministic and low-interaction with no real CMS or shell behavior

## GeoIP Files

Place these files in the local `./geoip` directory before starting the stack:

- `./geoip/GeoLite2-City.mmdb`
- `./geoip/GeoLite2-ASN.mmdb`

The app will still run without them, but country, city, coordinates, and ASN fields will be empty until the databases are present.

## Start The Stack

From the project directory:

```bash
docker compose build
docker compose up -d
```

Open the fake site at:

```text
http://localhost:8080/
```

Open the private dashboard at:

```text
http://localhost:8081/
```

Check service health:

```bash
curl http://localhost:8081/health
```

## API Examples

Fetch recent failed Cowrie logins from a country:

```bash
curl "http://localhost:8081/api/events?source=cowrie&event_type=cowrie.login.failed&country=United%20States&limit=50"
```

Fetch recent WordPress login attempts:

```bash
curl "http://localhost:8081/api/events?source=wordpress_web&event_type=wp_login_attempt&limit=20"
```

Fetch map-ready GeoJSON for a single IP:

```bash
curl "http://localhost:8081/api/geojson?src_ip=203.0.113.42"
```

Fetch summary stats for a date range:

```bash
curl "http://localhost:8081/api/summary?start=2026-03-01T00:00:00Z&end=2026-03-21T23:59:59Z"
```

## Web Honeypot Test Commands

Fetch the fake login page:

```bash
curl -i http://localhost:8080/wp-login.php
```

Submit a fake login:

```bash
curl -i -X POST http://localhost:8080/wp-login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "log=admin&pwd=Password123&redirect_to=%2Fwp-admin%2F&testcookie=1"
```

Check the wp-admin redirect:

```bash
curl -i http://localhost:8080/wp-admin
```

Probe XML-RPC:

```bash
curl -i -X POST http://localhost:8080/xmlrpc.php \
  -H "Content-Type: text/xml" \
  --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
```

Fetch the fake JSON API:

```bash
curl -i http://localhost:8080/wp-json
```

## Notes

- The compose stack uses lightweight Python services only. Nginx is not included to keep memory and CPU usage lower on a small ARM board.
- Compose now runs two lightweight services from the same image: a public honeypot on `:8080` and the dashboard/API on `:8081`.
- The Cowrie log directory is mounted read-only from `/opt/honeypot/cowrie/cowrie-var`.
- SQLite state is stored in `./data` so it persists across container restarts.
- TLS is best terminated by a reverse proxy or Cloudflare Tunnel in front of this container. The honeypot itself stays lightweight and speaks HTTP internally.
- The dashboard/API is on a separate port from the honeypot. If you want to restrict it later, you can bind it to localhost or place it behind a firewall or reverse proxy.
- Old events are deleted automatically after `EVENT_RETENTION_DAYS` to keep storage growth under control on small hardware.
- OpenStreetMap tiles and the Leaflet CDN require network access from the browser.
- Timestamps are normalized to UTC in the API and database. The browser will render them in the local timezone.

## Assumptions

- Cowrie writes newline-delimited JSON events to `/opt/honeypot/cowrie/cowrie-var/log/cowrie/cowrie.json`
- The app runs on the same host that has access to the Cowrie log directory
- HTTPS exposure will usually be handled by a reverse proxy or tunnel rather than native cert management inside the app container
- GeoIP enrichment is for approximate source geolocation only and should not be treated as attacker attribution
