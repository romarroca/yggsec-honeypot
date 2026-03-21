# Cowrie Map

Lightweight local web app for ingesting Cowrie JSON logs, enriching source IPs with local MaxMind GeoLite2 databases, storing parsed events in SQLite, and rendering an interactive Leaflet map.

## Project Layout

```text
.
├── app
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
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
- Enriches source IPs with local `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
- Stores parsed events in SQLite at `./data/cowrie_map.db`
- Prevents duplicate ingestion with a unique SHA-256 hash per log line
- Polls the Cowrie log every 15 seconds and only processes new complete lines
- Exposes `/health`, `/api/events`, `/api/summary`, and `/api/geojson`
- Serves a static Leaflet frontend from the same FastAPI container

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

Open the UI at:

```text
http://localhost:8080
```

Check service health:

```bash
curl http://localhost:8080/health
```

## API Examples

Fetch recent failed logins from a country:

```bash
curl "http://localhost:8080/api/events?eventid=cowrie.login.failed&country=United%20States&limit=50"
```

Fetch map-ready GeoJSON for a single IP:

```bash
curl "http://localhost:8080/api/geojson?src_ip=203.0.113.42"
```

Fetch summary stats for a date range:

```bash
curl "http://localhost:8080/api/summary?start=2026-03-01T00:00:00Z&end=2026-03-21T23:59:59Z"
```

## Notes

- The compose stack uses a single lightweight Python container. Nginx is not included to keep memory and CPU usage lower on a small ARM board.
- The Cowrie log directory is mounted read-only from `/opt/honeypot/cowrie/cowrie-var`.
- SQLite state is stored in `./data` so it persists across container restarts.
- OpenStreetMap tiles and the Leaflet CDN require network access from the browser.
- Timestamps are normalized to UTC in the API and database. The browser will render them in the local timezone.

## Assumptions

- Cowrie writes newline-delimited JSON events to `/opt/honeypot/cowrie/cowrie-var/log/cowrie/cowrie.json`
- The app runs on the same host that has access to the Cowrie log directory
- GeoIP enrichment is for approximate source geolocation only and should not be treated as attacker attribution
