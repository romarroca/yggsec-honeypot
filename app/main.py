import asyncio
import hashlib
import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote

import geoip2.database
from fastapi import FastAPI, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("cowrie-honeypot")

APP_DIR = Path(__file__).resolve().parent
BASE_DIR = APP_DIR.parent
DASHBOARD_DIR = BASE_DIR / "web"
TEMPLATE_DIR = APP_DIR / "templates"
HONEYPOT_THEME_DIR = APP_DIR / "honeypot_assets" / "theme"
HONEYPOT_UPLOADS_DIR = APP_DIR / "honeypot_assets" / "uploads"

DB_PATH = os.getenv("APP_DB_PATH", "/state/cowrie_map.db")
LOG_PATH = os.getenv(
    "COWRIE_LOG_PATH", "/cowrie/cowrie-var/log/cowrie/cowrie.json"
)
GEOIP_CITY_DB = os.getenv("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.getenv("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))
EVENT_RETENTION_DAYS = int(os.getenv("EVENT_RETENTION_DAYS", "90"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "21600"))
FAKE_SITE_NAME = os.getenv("FAKE_SITE_NAME", "Northwind Field Notes")
FAKE_TAGLINE = os.getenv(
    "FAKE_SITE_TAGLINE", "Home lab notes, blue team guides, and infrastructure journal."
)
FAKE_WORDPRESS_VERSION = os.getenv("FAKE_WORDPRESS_VERSION", "6.4.3")

SOURCE_ALL = "all"
SOURCE_COWRIE = "cowrie"
SOURCE_WORDPRESS = "wordpress_web"

ALLOWED_EVENT_IDS = {
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
}

EVENT_COLOR_MAP = {
    "cowrie.session.connect": "#2563eb",
    "cowrie.login.failed": "#f97316",
    "cowrie.login.success": "#16a34a",
    "cowrie.command.input": "#dc2626",
    "wp_login_page_view": "#0f766e",
    "wp_login_attempt": "#b91c1c",
    "wp_admin_access": "#0f766e",
    "xmlrpc_probe": "#1d4ed8",
    "wp_json_probe": "#0284c7",
    "generic_probe": "#475569",
    "static_asset_request": "#94a3b8",
}

SOURCE_MARKER_STYLE = {
    SOURCE_COWRIE: {"radius": 6, "fill_opacity": 0.78, "stroke_color": "#ffffff"},
    SOURCE_WORDPRESS: {"radius": 8, "fill_opacity": 0.55, "stroke_color": "#0f172a"},
}

MANAGEMENT_PREFIXES = ("/api", "/health", "/dashboard", "/dashboard-static")
MANAGEMENT_PATHS = {"/openapi.json", "/docs", "/redoc"}

FAKE_POSTS = {
    ("2025", "02", "lab-segmenting-a-home-office"): {
        "title": "Lab Notes: Segmenting a Home Office Without Making It Unusable",
        "date": "February 9, 2025",
        "author": "Mara Ellison",
        "excerpt": "A practical pass at splitting admin, media, and guest traffic without turning daily work into a routing puzzle.",
        "body": """
        <p>Small networks drift into complexity quietly. A printer lands on the wrong switch, a camera needs outbound DNS, and suddenly the "temporary" flat subnet is carrying everything.</p>
        <p>This week I moved the office stack into three zones: admin devices, general workstation traffic, and a guest segment for devices that only need outbound access. The design target was simple: reduce blast radius without breaking normal workflows.</p>
        <p>The useful lesson was not the VLAN math. It was documenting the handful of services that really cross boundaries: backups, mDNS replacements, and a short allow-list for dashboard traffic.</p>
        """,
    },
    ("2025", "01", "retention-rules-for-small-security-logs"): {
        "title": "Retention Rules for Small Security Logs",
        "date": "January 18, 2025",
        "author": "Mara Ellison",
        "excerpt": "How to keep enough telemetry to be useful on low-power hardware without hoarding months of noisy scan traffic.",
        "body": """
        <p>Low-cost systems are great until every service starts keeping every event forever. Retention on small hardware is less about policy language and more about keeping write amplification and disk churn predictable.</p>
        <p>For quick-turn lab sensors, I like a default window that keeps recent data hot and easy to query, then deletes old low-value records automatically. The point is to preserve trend visibility while staying lightweight enough to recover easily.</p>
        <p>If a signal matters for long-term analysis, ship it elsewhere. If it mostly helps with near-term triage, keep the local copy lean.</p>
        """,
    },
}

ABOUT_PAGE = {
    "title": "About",
    "body": """
    <p>Northwind Field Notes is a small operations journal focused on practical defense: lab hygiene, log handling, service hardening, and keeping lightweight infrastructure dependable.</p>
    <p>The site looks like a simple personal WordPress install because that is what a lot of opportunistic scanners expect to find. Underneath, it is a deterministic low-interaction web honeypot.</p>
    """,
}

LICENSE_TEXT = """Northwind Field Notes
License Summary

This site layout, sample writing, and decorative assets are provided for security research and deceptive service simulation in lab environments.

Permission is granted to copy, adapt, and redistribute the material for defensive research, training, and internal analysis, provided that recipients understand it is a simulated surface and not a functional publishing platform.

No warranty is provided. Use at your own risk. Do not treat any collected credentials as valid authentication data for a real system.
"""

ROBOTS_TEXT = """User-agent: *
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /wp-content/plugins/
Disallow: /wp-content/themes/
Disallow: /?s=
Allow: /wp-admin/admin-ajax.php
"""

WP_JSON_NAMESPACES = [
    "oembed/1.0",
    "wp/v2",
    "wp-site-health/v1",
]

EVENT_COLUMNS = {
    "source": "TEXT NOT NULL DEFAULT 'cowrie'",
    "event_type": "TEXT",
    "x_forwarded_for": "TEXT",
    "method": "TEXT",
    "path": "TEXT",
    "query_string": "TEXT",
    "headers_json": "TEXT",
    "user_agent": "TEXT",
    "referer": "TEXT",
    "status_code": "INTEGER",
    "response_size": "INTEGER",
}

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_timestamp(value: Any) -> str:
    if not value:
        return utc_now_iso()

    timestamp = str(value).strip()
    if timestamp.endswith("Z"):
        timestamp = timestamp.replace("Z", "+00:00")

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return str(value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def flatten_query_values(values: list[str] | None) -> list[str]:
    if not values:
        return []

    flattened: list[str] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                flattened.append(item)
    return flattened


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA synchronous=NORMAL;")
    connection.execute("PRAGMA foreign_keys=ON;")
    return connection


def ensure_event_columns(connection: sqlite3.Connection) -> None:
    existing_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(events)").fetchall()
    }
    for column_name, definition in EVENT_COLUMNS.items():
        if column_name not in existing_columns:
            connection.execute(
                f"ALTER TABLE events ADD COLUMN {column_name} {definition}"
            )


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'cowrie',
                eventid TEXT NOT NULL,
                event_type TEXT,
                session TEXT,
                src_ip TEXT,
                x_forwarded_for TEXT,
                method TEXT,
                path TEXT,
                query_string TEXT,
                headers_json TEXT,
                user_agent TEXT,
                referer TEXT,
                username TEXT,
                password TEXT,
                command TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                asn_number INTEGER,
                asn_org TEXT,
                status_code INTEGER,
                response_size INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS ingest_state (
                log_path TEXT PRIMARY KEY,
                inode INTEGER,
                offset INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            """
        )

        ensure_event_columns(connection)
        connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_source_timestamp ON events(source, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
            CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_events_country ON events(country);
            CREATE INDEX IF NOT EXISTS idx_events_asn ON events(asn_number);
            CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
            CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
            CREATE INDEX IF NOT EXISTS idx_events_user_agent ON events(user_agent);
            """
        )
        connection.execute(
            """
            UPDATE events
            SET source = COALESCE(NULLIF(source, ''), 'cowrie'),
                event_type = COALESCE(NULLIF(event_type, ''), eventid)
            """
        )
        connection.commit()


class GeoIPEnricher:
    def __init__(self, city_db_path: str, asn_db_path: str) -> None:
        self.city_reader = self._open_reader(city_db_path, "City")
        self.asn_reader = self._open_reader(asn_db_path, "ASN")

    @staticmethod
    def _open_reader(path: str, label: str) -> geoip2.database.Reader | None:
        if not Path(path).exists():
            logger.warning("%s database not found at %s", label, path)
            return None
        try:
            return geoip2.database.Reader(path)
        except Exception:
            logger.exception("Unable to load %s database at %s", label, path)
            return None

    def lookup(self, ip_address: str | None) -> dict[str, Any]:
        enriched = {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn_number": None,
            "asn_org": None,
        }
        if not ip_address:
            return enriched

        if self.city_reader:
            try:
                city_result = self.city_reader.city(ip_address)
                enriched["country"] = city_result.country.name
                enriched["city"] = city_result.city.name
                enriched["latitude"] = city_result.location.latitude
                enriched["longitude"] = city_result.location.longitude
            except Exception:
                logger.debug("City lookup skipped for %s", ip_address, exc_info=True)

        if self.asn_reader:
            try:
                asn_result = self.asn_reader.asn(ip_address)
                enriched["asn_number"] = asn_result.autonomous_system_number
                enriched["asn_org"] = asn_result.autonomous_system_organization
            except Exception:
                logger.debug("ASN lookup skipped for %s", ip_address, exc_info=True)

        return enriched

    def close(self) -> None:
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()


def cleanup_old_events(connection: sqlite3.Connection | None = None) -> int:
    if EVENT_RETENTION_DAYS <= 0:
        return 0

    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=EVENT_RETENTION_DAYS)
    ).isoformat().replace("+00:00", "Z")

    if connection is not None:
        before = connection.total_changes
        connection.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        return connection.total_changes - before

    with get_connection() as local_connection:
        before = local_connection.total_changes
        local_connection.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        local_connection.commit()
        return local_connection.total_changes - before


class CowrieIngestor:
    def __init__(self, log_path: str, geoip: GeoIPEnricher) -> None:
        self.log_path = log_path
        self.geoip = geoip
        self._lock = asyncio.Lock()
        self._last_cleanup = datetime.min.replace(tzinfo=timezone.utc)

    async def run_once(self) -> dict[str, int]:
        async with self._lock:
            return await asyncio.to_thread(self._run_once_sync)

    def _run_once_sync(self) -> dict[str, int]:
        stats = {"processed": 0, "inserted": 0, "duplicates": 0, "skipped": 0}
        log_file = Path(self.log_path)

        if not log_file.exists():
            self._maybe_cleanup()
            logger.warning("Cowrie log file not found at %s", self.log_path)
            return stats

        file_stat = log_file.stat()

        with get_connection() as connection, log_file.open("rb") as handle:
            state = connection.execute(
                "SELECT inode, offset FROM ingest_state WHERE log_path = ?",
                (self.log_path,),
            ).fetchone()

            offset = 0
            if state:
                saved_inode = state["inode"]
                saved_offset = int(state["offset"] or 0)
                if saved_inode == file_stat.st_ino and saved_offset <= file_stat.st_size:
                    offset = saved_offset

            handle.seek(offset)

            while True:
                line_start = handle.tell()
                raw_line = handle.readline()
                if not raw_line:
                    break
                if not raw_line.endswith(b"\n"):
                    handle.seek(line_start)
                    break

                offset = handle.tell()
                stats["processed"] += 1
                result = self._process_line(connection, raw_line)
                stats[result] += 1

            connection.execute(
                """
                INSERT INTO ingest_state (log_path, inode, offset, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(log_path) DO UPDATE SET
                    inode = excluded.inode,
                    offset = excluded.offset,
                    updated_at = excluded.updated_at
                """,
                (self.log_path, file_stat.st_ino, offset, utc_now_iso()),
            )
            deleted = self._maybe_cleanup(connection)
            connection.commit()

        if stats["processed"] or deleted:
            logger.info("Cowrie maintenance pass completed: %s, deleted=%s", stats, deleted)
        return stats

    def _maybe_cleanup(self, connection: sqlite3.Connection | None = None) -> int:
        now = datetime.now(timezone.utc)
        if (
            now - self._last_cleanup
        ).total_seconds() < CLEANUP_INTERVAL_SECONDS or EVENT_RETENTION_DAYS <= 0:
            return 0

        deleted = cleanup_old_events(connection)
        self._last_cleanup = now
        return deleted

    def _process_line(self, connection: sqlite3.Connection, raw_line: bytes) -> str:
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line:
            return "skipped"

        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed JSON line in Cowrie log")
            return "skipped"

        event_id = clean_text(payload.get("eventid"))
        if event_id not in ALLOWED_EVENT_IDS:
            return "skipped"

        src_ip = clean_text(payload.get("src_ip"))
        geo = self.geoip.lookup(src_ip)
        values = (
            hashlib.sha256(raw_line.rstrip(b"\n")).hexdigest(),
            normalize_timestamp(payload.get("timestamp")),
            SOURCE_COWRIE,
            event_id,
            event_id,
            clean_text(payload.get("session")),
            src_ip,
            clean_text(payload.get("username")),
            clean_text(payload.get("password")),
            clean_text(payload.get("input") or payload.get("command")),
            geo["country"],
            geo["city"],
            geo["latitude"],
            geo["longitude"],
            geo["asn_number"],
            clean_text(geo["asn_org"]),
        )

        before_changes = connection.total_changes
        connection.execute(
            """
            INSERT INTO events (
                event_hash,
                timestamp,
                source,
                eventid,
                event_type,
                session,
                src_ip,
                username,
                password,
                command,
                country,
                city,
                latitude,
                longitude,
                asn_number,
                asn_org
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_hash) DO NOTHING
            """,
            values,
        )
        return "inserted" if connection.total_changes > before_changes else "duplicates"

    async def poll_forever(self) -> None:
        while True:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Background ingestion pass failed")


def append_condition(where_clause: str, condition: str) -> str:
    if where_clause:
        return f"{where_clause} AND {condition}"
    return f"WHERE {condition}"


def combine_event_types(
    event_types: list[str] | None, event_ids: list[str] | None
) -> list[str]:
    combined = []
    for value in (event_types or []) + (event_ids or []):
        if value not in combined:
            combined.append(value)
    return combined


def build_filters(
    start: str | None,
    end: str | None,
    event_types: list[str],
    source: str,
    country: str | None,
    src_ip: str | None,
    path: str | None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    if start:
        clauses.append("timestamp >= ?")
        params.append(normalize_timestamp(start))
    if end:
        clauses.append("timestamp <= ?")
        params.append(normalize_timestamp(end))
    if event_types:
        placeholders = ", ".join("?" for _ in event_types)
        clauses.append(f"event_type IN ({placeholders})")
        params.extend(event_types)
    if source and source != SOURCE_ALL:
        clauses.append("source = ?")
        params.append(source)
    if country:
        clauses.append("LOWER(country) = LOWER(?)")
        params.append(country.strip())
    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip.strip())
    if path:
        clauses.append("path = ?")
        params.append(path.strip())

    if not clauses:
        return "", params
    return f"WHERE {' AND '.join(clauses)}", params


def marker_style_for_item(item: dict[str, Any]) -> dict[str, Any]:
    source_style = SOURCE_MARKER_STYLE.get(item["source"], SOURCE_MARKER_STYLE[SOURCE_COWRIE])
    return {
        "marker_color": EVENT_COLOR_MAP.get(item["event_type"], "#0f172a"),
        "marker_radius": source_style["radius"],
        "marker_fill_opacity": source_style["fill_opacity"],
        "marker_stroke_color": source_style["stroke_color"],
    }


def fetch_events(
    start: str | None,
    end: str | None,
    event_types: list[str],
    source: str,
    country: str | None,
    src_ip: str | None,
    path: str | None,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    where_clause, params = build_filters(
        start, end, event_types, source, country, src_ip, path
    )

    with get_connection() as connection:
        total = connection.execute(
            f"SELECT COUNT(*) AS count FROM events {where_clause}",
            params,
        ).fetchone()["count"]
        rows = connection.execute(
            f"""
            SELECT
                id,
                timestamp,
                source,
                eventid,
                event_type,
                session,
                src_ip,
                x_forwarded_for,
                method,
                path,
                query_string,
                headers_json,
                user_agent,
                referer,
                username,
                password,
                command,
                country,
                city,
                latitude,
                longitude,
                asn_number,
                asn_org,
                status_code,
                response_size
            FROM events
            {where_clause}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()

    items = [dict(row) for row in rows]
    for item in items:
        item.update(marker_style_for_item(item))
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def fetch_summary(
    start: str | None,
    end: str | None,
    event_types: list[str],
    source: str,
    country: str | None,
    src_ip: str | None,
    path: str | None,
) -> dict[str, Any]:
    where_clause, params = build_filters(
        start, end, event_types, source, country, src_ip, path
    )
    now = datetime.now(timezone.utc)
    last_24h = (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    last_7d = (now - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    last_30d = (now - timedelta(days=30)).isoformat().replace("+00:00", "Z")

    web_attempts_clause = append_condition(
        where_clause,
        "source = ? AND event_type = 'wp_login_attempt'",
    )
    web_attempts_params = [*params, SOURCE_WORDPRESS]

    with get_connection() as connection:
        totals = connection.execute(
            f"""
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) AS last_24h,
                SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) AS last_7d,
                SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) AS last_30d
            FROM events
            {where_clause}
            """,
            [last_24h, last_7d, last_30d, *params],
        ).fetchone()

        source_breakdown = connection.execute(
            f"""
            SELECT source, COUNT(*) AS count
            FROM events
            {where_clause}
            GROUP BY source
            ORDER BY count DESC, source ASC
            """,
            params,
        ).fetchall()

        top_countries = connection.execute(
            f"""
            SELECT country, COUNT(*) AS count
            FROM events
            {append_condition(where_clause, "country IS NOT NULL AND country <> ''")}
            GROUP BY country
            ORDER BY count DESC, country ASC
            LIMIT 10
            """,
            params,
        ).fetchall()

        top_asns = connection.execute(
            f"""
            SELECT asn_number, asn_org, COUNT(*) AS count
            FROM events
            {append_condition(where_clause, "asn_number IS NOT NULL")}
            GROUP BY asn_number, asn_org
            ORDER BY count DESC, asn_number ASC
            LIMIT 10
            """,
            params,
        ).fetchall()

        top_usernames = connection.execute(
            f"""
            SELECT username, COUNT(*) AS count
            FROM events
            {append_condition(where_clause, "username IS NOT NULL AND username <> ''")}
            GROUP BY username
            ORDER BY count DESC, username ASC
            LIMIT 10
            """,
            params,
        ).fetchall()

        event_breakdown = connection.execute(
            f"""
            SELECT event_type, COUNT(*) AS count
            FROM events
            {where_clause}
            GROUP BY event_type
            ORDER BY count DESC, event_type ASC
            """,
            params,
        ).fetchall()

        top_paths = connection.execute(
            f"""
            SELECT path, COUNT(*) AS count
            FROM events
            {append_condition(where_clause, "path IS NOT NULL AND path <> ''")}
            GROUP BY path
            ORDER BY count DESC, path ASC
            LIMIT 10
            """,
            params,
        ).fetchall()

        top_user_agents = connection.execute(
            f"""
            SELECT user_agent, COUNT(*) AS count
            FROM events
            {append_condition(where_clause, "user_agent IS NOT NULL AND user_agent <> ''")}
            GROUP BY user_agent
            ORDER BY count DESC, user_agent ASC
            LIMIT 10
            """,
            params,
        ).fetchall()

        recent_web_login_attempts = connection.execute(
            f"""
            SELECT
                timestamp,
                src_ip,
                country,
                username,
                password,
                path,
                user_agent,
                status_code,
                asn_org
            FROM events
            {web_attempts_clause}
            ORDER BY timestamp DESC, id DESC
            LIMIT 12
            """,
            web_attempts_params,
        ).fetchall()

        web_login_attempts_24h = connection.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM events
            {append_condition(web_attempts_clause, "timestamp >= ?")}
            """,
            [*web_attempts_params, last_24h],
        ).fetchone()["count"]

    return {
        "totals": {
            "total_events": totals["total_events"] or 0,
            "last_24h": totals["last_24h"] or 0,
            "last_7d": totals["last_7d"] or 0,
            "last_30d": totals["last_30d"] or 0,
            "web_login_attempts_24h": web_login_attempts_24h or 0,
        },
        "source_breakdown": [dict(row) for row in source_breakdown],
        "top_countries": [dict(row) for row in top_countries],
        "top_asns": [dict(row) for row in top_asns],
        "top_usernames": [dict(row) for row in top_usernames],
        "event_breakdown": [dict(row) for row in event_breakdown],
        "top_paths": [dict(row) for row in top_paths],
        "top_user_agents": [dict(row) for row in top_user_agents],
        "recent_web_login_attempts": [dict(row) for row in recent_web_login_attempts],
    }


def fetch_geojson(
    start: str | None,
    end: str | None,
    event_types: list[str],
    source: str,
    country: str | None,
    src_ip: str | None,
    path: str | None,
    limit: int,
) -> dict[str, Any]:
    result = fetch_events(
        start=start,
        end=end,
        event_types=event_types,
        source=source,
        country=country,
        src_ip=src_ip,
        path=path,
        limit=limit,
        offset=0,
    )
    features: list[dict[str, Any]] = []
    for item in result["items"]:
        if item.get("latitude") is None or item.get("longitude") is None:
            continue
        features.append(
            {
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [item["longitude"], item["latitude"]],
                },
                "properties": item,
            }
        )

    return {
        "type": "FeatureCollection",
        "features": features,
        "meta": {
            "total_events": result["total"],
            "returned_features": len(features),
            "limit": limit,
        },
    }


def build_template_context(request: Request, **extra: Any) -> dict[str, Any]:
    return {
        "request": request,
        "site_name": FAKE_SITE_NAME,
        "site_tagline": FAKE_TAGLINE,
        "wp_version": FAKE_WORDPRESS_VERSION,
        "theme_stylesheet": "/wp-content/themes/fieldnote/style.css",
        "logo_path": "/wp-content/uploads/2025/09/fieldnote-mark.svg",
        **extra,
    }


def site_base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def is_management_path(path: str) -> bool:
    return path in MANAGEMENT_PATHS or path.startswith(MANAGEMENT_PREFIXES)


def should_log_wordpress_request(path: str) -> bool:
    return not is_management_path(path)


def classify_wordpress_event(path: str, method: str) -> str:
    if path == "/wp-login.php":
        return "wp_login_attempt" if method.upper() == "POST" else "wp_login_page_view"
    if path == "/xmlrpc.php":
        return "xmlrpc_probe"
    if path.startswith("/wp-json"):
        return "wp_json_probe"
    if path == "/favicon.ico" or path.startswith("/wp-content/themes/fieldnote/") or path.startswith("/wp-content/uploads/"):
        return "static_asset_request"
    if path == "/wp-admin" or path.startswith("/wp-admin/"):
        return "wp_admin_access"
    return "generic_probe"


def serialize_headers(request: Request) -> str:
    normalized = {}
    for header_name, value in request.headers.items():
        normalized[header_name.lower()] = value[:512]
    return json.dumps(normalized, sort_keys=True)


def get_client_ip(request: Request) -> tuple[str | None, str | None]:
    cf_ip = clean_text(request.headers.get("cf-connecting-ip"))
    x_forwarded_for = clean_text(request.headers.get("x-forwarded-for"))
    if cf_ip:
        return cf_ip, x_forwarded_for
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip(), x_forwarded_for
    if request.client:
        return request.client.host, x_forwarded_for
    return None, x_forwarded_for


def parse_login_fields(raw_body: bytes) -> tuple[str | None, str | None]:
    if not raw_body:
        return None, None
    try:
        parsed = parse_qs(raw_body.decode("utf-8", errors="replace"), keep_blank_values=True)
    except Exception:
        return None, None
    username = parsed.get("log", parsed.get("username", [None]))[0]
    password = parsed.get("pwd", parsed.get("password", [None]))[0]
    return clean_text(username), clean_text(password)


def get_response_size(response: Response) -> int:
    content_length = response.headers.get("content-length")
    if content_length and content_length.isdigit():
        return int(content_length)
    body = getattr(response, "body", None)
    if isinstance(body, (bytes, bytearray)):
        return len(body)
    if isinstance(body, str):
        return len(body.encode("utf-8"))
    return 0


def insert_web_event(
    *,
    geoip: GeoIPEnricher,
    timestamp: str,
    src_ip: str | None,
    x_forwarded_for: str | None,
    method: str,
    path: str,
    query_string: str,
    headers_json: str,
    user_agent: str | None,
    referer: str | None,
    username: str | None,
    password: str | None,
    event_type: str,
    status_code: int,
    response_size: int,
) -> None:
    geo = geoip.lookup(src_ip)
    payload = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "x_forwarded_for": x_forwarded_for,
        "method": method,
        "path": path,
        "query_string": query_string,
        "user_agent": user_agent,
        "referer": referer,
        "username": username,
        "password": password,
        "event_type": event_type,
        "status_code": status_code,
        "response_size": response_size,
    }
    event_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
    ).hexdigest()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO events (
                event_hash,
                timestamp,
                source,
                eventid,
                event_type,
                src_ip,
                x_forwarded_for,
                method,
                path,
                query_string,
                headers_json,
                user_agent,
                referer,
                username,
                password,
                country,
                city,
                latitude,
                longitude,
                asn_number,
                asn_org,
                status_code,
                response_size
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_hash) DO NOTHING
            """,
            (
                event_hash,
                timestamp,
                SOURCE_WORDPRESS,
                event_type,
                event_type,
                src_ip,
                x_forwarded_for,
                method,
                path,
                query_string,
                headers_json,
                user_agent,
                referer,
                username,
                password,
                geo["country"],
                geo["city"],
                geo["latitude"],
                geo["longitude"],
                geo["asn_number"],
                clean_text(geo["asn_org"]),
                status_code,
                response_size,
            ),
        )
        connection.commit()


async def log_wordpress_request(request: Request, response: Response) -> None:
    timestamp = utc_now_iso()
    path = request.url.path
    event_type = classify_wordpress_event(path, request.method)
    src_ip, x_forwarded_for = get_client_ip(request)
    username = None
    password = None

    if path == "/wp-login.php" and request.method.upper() == "POST":
        username, password = parse_login_fields(getattr(request.state, "raw_body", b""))

    insert_web_event(
        geoip=request.app.state.geoip,
        timestamp=timestamp,
        src_ip=src_ip,
        x_forwarded_for=x_forwarded_for,
        method=request.method.upper(),
        path=path,
        query_string=request.url.query,
        headers_json=serialize_headers(request),
        user_agent=clean_text(request.headers.get("user-agent")),
        referer=clean_text(request.headers.get("referer")),
        username=username,
        password=password,
        event_type=event_type,
        status_code=response.status_code,
        response_size=get_response_size(response),
    )


def login_redirect_path(path: str) -> str:
    return f"/wp-login.php?redirect_to={quote(path, safe='')}"


def render_status_page(
    request: Request,
    *,
    title: str,
    headline: str,
    message: str,
    status_code: int = 200,
) -> HTMLResponse:
    context = build_template_context(
        request,
        page_title=title,
        headline=headline,
        message=message,
    )
    return templates.TemplateResponse("wp_status.html", context, status_code=status_code)


def build_xmlrpc_payload(raw_body: str) -> str:
    if "system.listMethods" in raw_body:
        return """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>system.listMethods</string></value>
            <value><string>system.multicall</string></value>
            <value><string>wp.getUsersBlogs</string></value>
            <value><string>metaWeblog.newPost</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>"""

    if "pingback.ping" in raw_body:
        return """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>49</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Pingbacks are not available.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>"""

    return """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>4</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Unknown XML-RPC method.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    cleanup_old_events()
    geoip = GeoIPEnricher(GEOIP_CITY_DB, GEOIP_ASN_DB)
    ingestor = CowrieIngestor(LOG_PATH, geoip)
    app.state.geoip = geoip
    app.state.ingestor = ingestor

    await ingestor.run_once()
    poller = asyncio.create_task(ingestor.poll_forever())
    app.state.poller = poller

    try:
        yield
    finally:
        poller.cancel()
        try:
            await poller
        except asyncio.CancelledError:
            pass
        geoip.close()


app = FastAPI(
    title="Cowrie and WordPress Honeypot",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.mount("/dashboard-static", StaticFiles(directory=DASHBOARD_DIR), name="dashboard-static")


@app.middleware("http")
async def wordpress_request_logger(request: Request, call_next):
    should_capture_body = should_log_wordpress_request(request.url.path) and request.method.upper() in {
        "POST",
        "PUT",
        "PATCH",
    }
    request.state.raw_body = b""

    if should_capture_body:
        body = await request.body()
        request.state.raw_body = body

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive

    response = await call_next(request)
    if should_log_wordpress_request(request.url.path):
        try:
            await log_wordpress_request(request, response)
        except Exception:
            logger.exception("Failed to log WordPress honeypot request")
    return response


@app.get("/health")
async def health() -> dict[str, Any]:
    with get_connection() as connection:
        counts = connection.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN source = ? THEN 1 ELSE 0 END) AS cowrie_events,
                SUM(CASE WHEN source = ? THEN 1 ELSE 0 END) AS wordpress_events
            FROM events
            """,
            (SOURCE_COWRIE, SOURCE_WORDPRESS),
        ).fetchone()
        state = connection.execute(
            "SELECT offset, updated_at FROM ingest_state WHERE log_path = ?",
            (LOG_PATH,),
        ).fetchone()

    return {
        "status": "ok",
        "log_path": LOG_PATH,
        "log_exists": Path(LOG_PATH).exists(),
        "db_path": DB_PATH,
        "geoip_city_db": Path(GEOIP_CITY_DB).exists(),
        "geoip_asn_db": Path(GEOIP_ASN_DB).exists(),
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "event_retention_days": EVENT_RETENTION_DAYS,
        "total_events": counts["total_events"] or 0,
        "cowrie_events": counts["cowrie_events"] or 0,
        "wordpress_events": counts["wordpress_events"] or 0,
        "ingest_state": dict(state) if state else None,
    }


@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/api/events")
async def api_events(
    start: str | None = None,
    end: str | None = None,
    event_type: list[str] | None = Query(default=None),
    eventid: list[str] | None = Query(default=None),
    source: str = Query(default=SOURCE_ALL),
    country: str | None = None,
    src_ip: str | None = None,
    path: str | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    return fetch_events(
        start=start,
        end=end,
        event_types=combine_event_types(flatten_query_values(event_type), flatten_query_values(eventid)),
        source=source,
        country=country,
        src_ip=src_ip,
        path=path,
        limit=limit,
        offset=offset,
    )


@app.get("/api/summary")
async def api_summary(
    start: str | None = None,
    end: str | None = None,
    event_type: list[str] | None = Query(default=None),
    eventid: list[str] | None = Query(default=None),
    source: str = Query(default=SOURCE_ALL),
    country: str | None = None,
    src_ip: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    return fetch_summary(
        start=start,
        end=end,
        event_types=combine_event_types(flatten_query_values(event_type), flatten_query_values(eventid)),
        source=source,
        country=country,
        src_ip=src_ip,
        path=path,
    )


@app.get("/api/geojson")
async def api_geojson(
    start: str | None = None,
    end: str | None = None,
    event_type: list[str] | None = Query(default=None),
    eventid: list[str] | None = Query(default=None),
    source: str = Query(default=SOURCE_ALL),
    country: str | None = None,
    src_ip: str | None = None,
    path: str | None = None,
    limit: int = Query(default=2500, ge=1, le=10000),
) -> dict[str, Any]:
    return fetch_geojson(
        start=start,
        end=end,
        event_types=combine_event_types(flatten_query_values(event_type), flatten_query_values(eventid)),
        source=source,
        country=country,
        src_ip=src_ip,
        path=path,
        limit=limit,
    )


@app.get("/", include_in_schema=False)
async def honeypot_home(request: Request) -> HTMLResponse:
    posts = [
        {
            "url": f"/{year}/{month}/{slug}/",
            "title": details["title"],
            "date": details["date"],
            "excerpt": details["excerpt"],
        }
        for (year, month, slug), details in FAKE_POSTS.items()
    ]
    context = build_template_context(
        request,
        page_title=FAKE_SITE_NAME,
        hero_title="Practical notes from a small blue team lab",
        posts=posts,
    )
    return templates.TemplateResponse("wp_home.html", context)


@app.get("/about/", include_in_schema=False)
async def about_page(request: Request) -> HTMLResponse:
    context = build_template_context(
        request,
        page_title=ABOUT_PAGE["title"],
        headline=ABOUT_PAGE["title"],
        article_body=ABOUT_PAGE["body"],
        article_date="Updated March 2026",
    )
    return templates.TemplateResponse("wp_post.html", context)


@app.get("/{year}/{month}/{slug}/", include_in_schema=False)
async def fake_post(request: Request, year: str, month: str, slug: str) -> HTMLResponse:
    post = FAKE_POSTS.get((year, month, slug))
    if not post:
        return render_status_page(
            request,
            title="Not Found",
            headline="Page not found",
            message="The page you requested could not be found.",
            status_code=404,
        )
    context = build_template_context(
        request,
        page_title=post["title"],
        headline=post["title"],
        article_body=post["body"],
        article_date=post["date"],
        article_author=post["author"],
    )
    return templates.TemplateResponse("wp_post.html", context)


@app.get("/wp-login.php", include_in_schema=False)
async def wp_login(request: Request) -> HTMLResponse:
    action = request.query_params.get("action", "")
    redirect_to = request.query_params.get("redirect_to", "/wp-admin/")
    context = build_template_context(
        request,
        page_title="Log In",
        action=action,
        redirect_to=redirect_to,
        error_message=None,
    )
    response = templates.TemplateResponse("wp_login.html", context)
    response.set_cookie("wordpress_test_cookie", "WP Cookie check", samesite="lax")
    return response


@app.post("/wp-login.php", include_in_schema=False)
async def wp_login_attempt(request: Request) -> HTMLResponse:
    form_values = parse_qs(
        getattr(request.state, "raw_body", b"").decode("utf-8", errors="replace"),
        keep_blank_values=True,
    )
    action = form_values.get("action", [request.query_params.get("action", "")])[0]
    redirect_to = form_values.get("redirect_to", [request.query_params.get("redirect_to", "/wp-admin/")])[0]
    username = clean_text(form_values.get("log", [""])[0])

    if action == "lostpassword":
        context = build_template_context(
            request,
            page_title="Password Recovery",
            action=action,
            redirect_to=redirect_to,
            recovery_notice="If that account exists, recovery guidance has been queued for review.",
            error_message=None,
            last_username=username,
        )
        response = templates.TemplateResponse("wp_login.html", context)
        response.set_cookie("wordpress_test_cookie", "WP Cookie check", samesite="lax")
        return response

    context = build_template_context(
        request,
        page_title="Log In",
        action=action,
        redirect_to=redirect_to,
        error_message="The credentials you entered could not be verified. Please try again.",
        last_username=username,
    )
    response = templates.TemplateResponse("wp_login.html", context, status_code=200)
    response.set_cookie("wordpress_test_cookie", "WP Cookie check", samesite="lax")
    return response


@app.api_route("/wp-admin", methods=["GET", "POST", "HEAD"], include_in_schema=False)
@app.api_route("/wp-admin/", methods=["GET", "POST", "HEAD"], include_in_schema=False)
async def wp_admin(request: Request) -> RedirectResponse:
    return RedirectResponse(url=login_redirect_path("/wp-admin/"), status_code=302)


@app.api_route("/wp-admin/install.php", methods=["GET", "POST", "HEAD"], include_in_schema=False)
async def wp_admin_install(request: Request) -> HTMLResponse:
    return render_status_page(
        request,
        title="Already Installed",
        headline="WordPress is already installed.",
        message="This site appears to be configured already. Log in to continue managing content.",
        status_code=200,
    )


@app.api_route("/wp-admin/{subpath:path}", methods=["GET", "POST", "HEAD"], include_in_schema=False)
async def wp_admin_subpaths(subpath: str) -> RedirectResponse:
    target = f"/wp-admin/{subpath}".rstrip("/") or "/wp-admin/"
    if not target.endswith("/") and "." not in Path(target).name:
        target = f"{target}/"
    return RedirectResponse(url=login_redirect_path(target), status_code=302)


@app.api_route("/xmlrpc.php", methods=["GET", "POST", "HEAD"], include_in_schema=False)
async def xmlrpc_endpoint(request: Request) -> Response:
    if request.method.upper() != "POST":
        return PlainTextResponse(
            "XML-RPC endpoint expects POST requests.",
            status_code=405,
            headers={"Allow": "POST"},
        )

    body_text = getattr(request.state, "raw_body", b"").decode("utf-8", errors="replace")
    return Response(
        content=build_xmlrpc_payload(body_text),
        media_type="text/xml",
        status_code=200,
    )


@app.get("/wp-json", include_in_schema=False)
@app.get("/wp-json/", include_in_schema=False)
async def wp_json(request: Request) -> JSONResponse:
    base_url = site_base_url(request)
    return JSONResponse(
        {
            "name": FAKE_SITE_NAME,
            "description": FAKE_TAGLINE,
            "url": base_url,
            "home": base_url,
            "gmt_offset": 0,
            "generator": f"WordPress {FAKE_WORDPRESS_VERSION}",
            "namespaces": WP_JSON_NAMESPACES,
            "routes": {
                "/": {"namespace": "", "methods": ["GET"]},
                "/wp/v2/posts": {"namespace": "wp/v2", "methods": ["GET"]},
                "/oembed/1.0/embed": {"namespace": "oembed/1.0", "methods": ["GET"]},
            },
        }
    )


@app.get("/readme.html", include_in_schema=False)
async def readme_page(request: Request) -> HTMLResponse:
    context = build_template_context(
        request,
        page_title="Readme",
        version_hint=FAKE_WORDPRESS_VERSION,
        theme_name="Fieldnote",
    )
    return templates.TemplateResponse("wp_readme.html", context)


@app.get("/license.txt", include_in_schema=False)
async def license_txt() -> PlainTextResponse:
    return PlainTextResponse(LICENSE_TEXT)


@app.get("/robots.txt", include_in_schema=False)
async def robots_txt() -> PlainTextResponse:
    return PlainTextResponse(ROBOTS_TEXT)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> RedirectResponse:
    return RedirectResponse("/wp-content/uploads/2025/09/fieldnote-mark.svg", status_code=302)


@app.get("/wp-content", include_in_schema=False)
@app.get("/wp-content/", include_in_schema=False)
async def wp_content_root(request: Request) -> HTMLResponse:
    return render_status_page(
        request,
        title="Access Denied",
        headline="Directory access is not available.",
        message="Static content is published directly by the application and directory indexes are disabled.",
        status_code=403,
    )


@app.get("/wp-content/plugins/", include_in_schema=False)
@app.get("/wp-content/themes/", include_in_schema=False)
@app.get("/wp-content/uploads/", include_in_schema=False)
async def wp_content_subdirs(request: Request) -> HTMLResponse:
    return render_status_page(
        request,
        title="Access Denied",
        headline="Directory browsing is disabled.",
        message="The requested content is not available through directory indexes.",
        status_code=403,
    )


@app.get("/wp-includes/", include_in_schema=False)
async def wp_includes(request: Request) -> HTMLResponse:
    return render_status_page(
        request,
        title="Forbidden",
        headline="Direct access to this area is restricted.",
        message="Core include paths are not exposed for direct browsing.",
        status_code=403,
    )


app.mount("/wp-content/themes/fieldnote", StaticFiles(directory=HONEYPOT_THEME_DIR), name="wp-theme")
app.mount("/wp-content/uploads", StaticFiles(directory=HONEYPOT_UPLOADS_DIR), name="wp-uploads")


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], include_in_schema=False)
async def honeypot_not_found(request: Request, full_path: str) -> Response:
    if is_management_path(request.url.path):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return render_status_page(
        request,
        title="Not Found",
        headline="Nothing matched that request.",
        message="The requested page could not be located on this server.",
        status_code=404,
    )
