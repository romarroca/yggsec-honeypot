const map = L.map("map", {
  zoomControl: true,
  worldCopyJump: true,
}).setView([20, 0], 2);

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 19,
  attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
}).addTo(map);

const markerLayer = L.layerGroup().addTo(map);

const filtersForm = document.getElementById("filters");
const refreshButton = document.getElementById("refreshButton");
const resetButton = document.getElementById("resetButton");
const statusBadge = document.getElementById("statusBadge");
const mapMeta = document.getElementById("mapMeta");

const summaryTargets = {
  totalEvents: document.getElementById("totalEvents"),
  last24h: document.getElementById("last24h"),
  last7d: document.getElementById("last7d"),
  last30d: document.getElementById("last30d"),
  webLogins24h: document.getElementById("webLogins24h"),
  topCountries: document.getElementById("topCountries"),
  topAsns: document.getElementById("topAsns"),
  topUsernames: document.getElementById("topUsernames"),
  eventBreakdown: document.getElementById("eventBreakdown"),
  topPaths: document.getElementById("topPaths"),
  topUserAgents: document.getElementById("topUserAgents"),
  recentWebLogins: document.getElementById("recentWebLogins"),
};

const state = {
  refreshTimer: null,
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatCount(value) {
  return Number(value || 0).toLocaleString();
}

function datetimeLocalToIso(value) {
  if (!value) {
    return "";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "";
  }
  return parsed.toISOString();
}

function collectFilters() {
  const start = datetimeLocalToIso(document.getElementById("start").value);
  const end = datetimeLocalToIso(document.getElementById("end").value);
  const source = document.getElementById("source").value.trim();
  const event_type = document.getElementById("eventType").value.trim();
  const country = document.getElementById("country").value.trim();
  const src_ip = document.getElementById("src_ip").value.trim();

  return { start, end, source, event_type, country, src_ip };
}

function buildQuery(filters, extra = {}) {
  const params = new URLSearchParams();

  Object.entries({ ...filters, ...extra }).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, value);
    }
  });

  return params.toString() ? `?${params.toString()}` : "";
}

function renderList(element, items, formatter, emptyLabel) {
  element.innerHTML = "";

  if (!items || items.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = emptyLabel;
    element.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    li.innerHTML = formatter(item);
    element.appendChild(li);
  });
}

function renderSummary(summary) {
  summaryTargets.totalEvents.textContent = formatCount(summary.totals.total_events);
  summaryTargets.last24h.textContent = formatCount(summary.totals.last_24h);
  summaryTargets.last7d.textContent = formatCount(summary.totals.last_7d);
  summaryTargets.last30d.textContent = formatCount(summary.totals.last_30d);
  summaryTargets.webLogins24h.textContent = formatCount(summary.totals.web_login_attempts_24h);

  renderList(
    summaryTargets.topCountries,
    summary.top_countries,
    (item) =>
      `<span>${escapeHtml(item.country)}</span><strong>${formatCount(item.count)}</strong>`,
    "No country data yet"
  );

  renderList(
    summaryTargets.topAsns,
    summary.top_asns,
    (item) =>
      `<span>AS${escapeHtml(item.asn_number)} ${escapeHtml(item.asn_org || "Unknown")}</span><strong>${formatCount(item.count)}</strong>`,
    "No ASN data yet"
  );

  renderList(
    summaryTargets.topUsernames,
    summary.top_usernames,
    (item) =>
      `<span>${escapeHtml(item.username)}</span><strong>${formatCount(item.count)}</strong>`,
    "No usernames captured yet"
  );

  renderList(
    summaryTargets.eventBreakdown,
    summary.event_breakdown,
    (item) =>
      `<span>${escapeHtml(item.event_type)}</span><strong>${formatCount(item.count)}</strong>`,
    "No matching events"
  );

  renderList(
    summaryTargets.topPaths,
    summary.top_paths,
    (item) =>
      `<span>${escapeHtml(item.path)}</span><strong>${formatCount(item.count)}</strong>`,
    "No path data yet"
  );

  renderList(
    summaryTargets.topUserAgents,
    summary.top_user_agents,
    (item) =>
      `<span>${escapeHtml(item.user_agent)}</span><strong>${formatCount(item.count)}</strong>`,
    "No user-agent data yet"
  );

  renderList(
    summaryTargets.recentWebLogins,
    summary.recent_web_login_attempts,
    (item) =>
      `<div><span>${escapeHtml(item.timestamp)}</span><strong>${escapeHtml(item.src_ip || "unknown")}</strong></div><small>${escapeHtml(item.username || "-")} / ${escapeHtml(item.password || "-")} • ${escapeHtml(item.path || "/wp-login.php")}</small>`,
    "No recent WordPress login attempts"
  );
}

function popupHtml(properties) {
  const details = [
    ["Timestamp", properties.timestamp],
    ["Source", properties.source],
    ["Event", properties.eventid],
    ["Source IP", properties.src_ip],
    ["Method", properties.method],
    ["Path", properties.path],
    ["Country", properties.country],
    ["City", properties.city],
    ["ASN", properties.asn_number ? `AS${properties.asn_number}` : ""],
    ["ASN Org", properties.asn_org],
    ["Username", properties.username],
    ["Password", properties.password],
    ["Command", properties.command],
  ]
    .filter(([, value]) => value)
    .map(
      ([label, value]) =>
        `<div class="popup-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`
    )
    .join("");

  return `<div class="popup-card">${details || "<p>No event details available.</p>"}</div>`;
}

function renderGeoJson(geojson) {
  markerLayer.clearLayers();

  if (!geojson.features || geojson.features.length === 0) {
    mapMeta.textContent = "No geolocated events matched the current filters.";
    return;
  }

  const bounds = [];

  geojson.features.forEach((feature) => {
    const [longitude, latitude] = feature.geometry.coordinates;
    const { marker_color: markerColor, ...properties } = feature.properties;

    const marker = L.circleMarker([latitude, longitude], {
      radius: properties.marker_radius || 6,
      color: properties.marker_stroke_color || markerColor || "#0f172a",
      weight: 2,
      fillColor: markerColor || "#0f172a",
      fillOpacity: properties.marker_fill_opacity || 0.75,
    });

    marker.bindPopup(popupHtml(properties), {
      maxWidth: 360,
    });

    marker.addTo(markerLayer);
    bounds.push([latitude, longitude]);
  });

  if (bounds.length > 0) {
    map.fitBounds(bounds, { padding: [30, 30], maxZoom: 5 });
  }

  const total = formatCount(geojson.meta.total_events);
  const visible = formatCount(geojson.meta.returned_features);
  mapMeta.textContent = `${visible} mapped points returned from ${total} matching events.`;
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function sourceBreakdownLabel(summary) {
  if (!summary.source_breakdown || summary.source_breakdown.length === 0) {
    return "";
  }

  return summary.source_breakdown
    .map((item) => `${item.source}: ${formatCount(item.count)}`)
    .join(" • ");
}

async function refreshDashboard() {
  const filters = collectFilters();
  statusBadge.textContent = "Refreshing";
  statusBadge.dataset.state = "busy";

  try {
    const [summary, geojson] = await Promise.all([
      fetchJson(`/api/summary${buildQuery(filters)}`),
      fetchJson(`/api/geojson${buildQuery(filters, { limit: 2500 })}`),
    ]);

    renderSummary(summary);
    renderGeoJson(geojson);
    const breakdown = sourceBreakdownLabel(summary);
    if (breakdown) {
      mapMeta.textContent = `${mapMeta.textContent} ${breakdown}`;
    }
    statusBadge.textContent = "Live";
    statusBadge.dataset.state = "live";
  } catch (error) {
    console.error(error);
    statusBadge.textContent = "Error";
    statusBadge.dataset.state = "error";
    mapMeta.textContent = "The API request failed. Check the backend container logs.";
  }
}

filtersForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await refreshDashboard();
});

refreshButton.addEventListener("click", async () => {
  await refreshDashboard();
});

resetButton.addEventListener("click", async () => {
  filtersForm.reset();
  await refreshDashboard();
});

window.addEventListener("load", async () => {
  await refreshDashboard();

  state.refreshTimer = window.setInterval(async () => {
    await refreshDashboard();
  }, 30000);
});
