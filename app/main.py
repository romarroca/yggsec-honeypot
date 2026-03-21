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

import geoip2.database
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("cowrie-map")

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"

DB_PATH = os.getenv("APP_DB_PATH", "/state/cowrie_map.db")
LOG_PATH = os.getenv(
    "COWRIE_LOG_PATH", "/cowrie/cowrie-var/log/cowrie/cowrie.json"
)
GEOIP_CITY_DB = os.getenv("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.getenv("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))

ALLOWED_EVENT_IDS = {
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
}

EVENT_COLOR_MAP = {
    "cowrie.session.connect": "#3b82f6",
    "cowrie.login.failed": "#f97316",
    "cowrie.login.success": "#16a34a",
    "cowrie.command.input": "#dc2626",
}


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


def init_db() -> None:
    state_dir = Path(DB_PATH).parent
    state_dir.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                eventid TEXT NOT NULL,
                session TEXT,
                src_ip TEXT,
                username TEXT,
                password TEXT,
                command TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                asn_number INTEGER,
                asn_org TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
            CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_events_country ON events(country);
            CREATE INDEX IF NOT EXISTS idx_events_asn ON events(asn_number);

            CREATE TABLE IF NOT EXISTS ingest_state (
                log_path TEXT PRIMARY KEY,
                inode INTEGER,
                offset INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            """
        )


class GeoIPEnricher:
    def __init__(self, city_db_path: str, asn_db_path: str) -> None:
        self.city_db_path = city_db_path
        self.asn_db_path = asn_db_path
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


class CowrieIngestor:
    def __init__(self, log_path: str, geoip: GeoIPEnricher) -> None:
        self.log_path = log_path
        self.geoip = geoip
        self._lock = asyncio.Lock()

    async def run_once(self) -> dict[str, int]:
        async with self._lock:
            return await asyncio.to_thread(self._run_once_sync)

    def _run_once_sync(self) -> dict[str, int]:
        stats = {"processed": 0, "inserted": 0, "duplicates": 0, "skipped": 0}
        log_file = Path(self.log_path)

        if not log_file.exists():
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
            connection.commit()

        if stats["processed"]:
            logger.info("Ingestion pass completed: %s", stats)
        return stats

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
                eventid,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_hash) DO NOTHING
            """,
            values,
        )

        if connection.total_changes > before_changes:
            return "inserted"
        return "duplicates"

    async def poll_forever(self) -> None:
        while True:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Background ingestion pass failed")


def build_filters(
    start: str | None,
    end: str | None,
    event_ids: list[str],
    country: str | None,
    src_ip: str | None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    if start:
        clauses.append("timestamp >= ?")
        params.append(normalize_timestamp(start))

    if end:
        clauses.append("timestamp <= ?")
        params.append(normalize_timestamp(end))

    if event_ids:
        placeholders = ", ".join("?" for _ in event_ids)
        clauses.append(f"eventid IN ({placeholders})")
        params.extend(event_ids)

    if country:
        clauses.append("LOWER(country) = LOWER(?)")
        params.append(country.strip())

    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip.strip())

    if not clauses:
        return "", params

    return f"WHERE {' AND '.join(clauses)}", params


def fetch_events(
    start: str | None,
    end: str | None,
    event_ids: list[str],
    country: str | None,
    src_ip: str | None,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    where_clause, params = build_filters(start, end, event_ids, country, src_ip)

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
                eventid,
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
            FROM events
            {where_clause}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()

    items = [dict(row) for row in rows]
    for item in items:
        item["marker_color"] = EVENT_COLOR_MAP.get(item["eventid"], "#0f172a")

    return {"items": items, "total": total, "limit": limit, "offset": offset}


def fetch_summary(
    start: str | None,
    end: str | None,
    event_ids: list[str],
    country: str | None,
    src_ip: str | None,
) -> dict[str, Any]:
    where_clause, params = build_filters(start, end, event_ids, country, src_ip)
    now = datetime.now(timezone.utc)
    last_24h = (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    last_7d = (now - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    last_30d = (now - timedelta(days=30)).isoformat().replace("+00:00", "Z")

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

        top_countries = connection.execute(
            f"""
            SELECT country, COUNT(*) AS count
            FROM events
            {where_clause} {"AND" if where_clause else "WHERE"} country IS NOT NULL AND country <> ''
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
            {where_clause} {"AND" if where_clause else "WHERE"} asn_number IS NOT NULL
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
            {where_clause} {"AND" if where_clause else "WHERE"} username IS NOT NULL AND username <> ''
            GROUP BY username
            ORDER BY count DESC, username ASC
            LIMIT 10
            """,
            params,
        ).fetchall()

        event_breakdown = connection.execute(
            f"""
            SELECT eventid, COUNT(*) AS count
            FROM events
            {where_clause}
            GROUP BY eventid
            ORDER BY count DESC, eventid ASC
            """,
            params,
        ).fetchall()

    return {
        "totals": {
            "total_events": totals["total_events"] or 0,
            "last_24h": totals["last_24h"] or 0,
            "last_7d": totals["last_7d"] or 0,
            "last_30d": totals["last_30d"] or 0,
        },
        "top_countries": [dict(row) for row in top_countries],
        "top_asns": [dict(row) for row in top_asns],
        "top_usernames": [dict(row) for row in top_usernames],
        "event_breakdown": [dict(row) for row in event_breakdown],
    }


def fetch_geojson(
    start: str | None,
    end: str | None,
    event_ids: list[str],
    country: str | None,
    src_ip: str | None,
    limit: int,
) -> dict[str, Any]:
    result = fetch_events(start, end, event_ids, country, src_ip, limit=limit, offset=0)

    features: list[dict[str, Any]] = []
    for item in result["items"]:
        latitude = item.get("latitude")
        longitude = item.get("longitude")
        if latitude is None or longitude is None:
            continue

        feature = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [longitude, latitude],
            },
            "properties": item,
        }
        features.append(feature)

    return {
        "type": "FeatureCollection",
        "features": features,
        "meta": {
            "total_events": result["total"],
            "returned_features": len(features),
            "limit": limit,
        },
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
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
    title="Cowrie Map",
    description="Lightweight Cowrie event ingestion and geolocation API.",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, Any]:
    log_exists = Path(LOG_PATH).exists()
    with get_connection() as connection:
        state = connection.execute(
            "SELECT offset, updated_at FROM ingest_state WHERE log_path = ?",
            (LOG_PATH,),
        ).fetchone()
        total_events = connection.execute("SELECT COUNT(*) AS count FROM events").fetchone()[
            "count"
        ]

    return {
        "status": "ok",
        "log_path": LOG_PATH,
        "log_exists": log_exists,
        "db_path": DB_PATH,
        "geoip_city_db": Path(GEOIP_CITY_DB).exists(),
        "geoip_asn_db": Path(GEOIP_ASN_DB).exists(),
        "ingest_state": dict(state) if state else None,
        "total_events": total_events,
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
    }


@app.get("/api/events")
async def api_events(
    start: str | None = None,
    end: str | None = None,
    eventid: list[str] | None = Query(default=None),
    country: str | None = None,
    src_ip: str | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    return fetch_events(
        start=start,
        end=end,
        event_ids=flatten_query_values(eventid),
        country=country,
        src_ip=src_ip,
        limit=limit,
        offset=offset,
    )


@app.get("/api/summary")
async def api_summary(
    start: str | None = None,
    end: str | None = None,
    eventid: list[str] | None = Query(default=None),
    country: str | None = None,
    src_ip: str | None = None,
) -> dict[str, Any]:
    return fetch_summary(
        start=start,
        end=end,
        event_ids=flatten_query_values(eventid),
        country=country,
        src_ip=src_ip,
    )


@app.get("/api/geojson")
async def api_geojson(
    start: str | None = None,
    end: str | None = None,
    eventid: list[str] | None = Query(default=None),
    country: str | None = None,
    src_ip: str | None = None,
    limit: int = Query(default=2500, ge=1, le=10000),
) -> dict[str, Any]:
    return fetch_geojson(
        start=start,
        end=end,
        event_ids=flatten_query_values(eventid),
        country=country,
        src_ip=src_ip,
        limit=limit,
    )
