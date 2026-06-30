import "./styles.css";

const API_BASE = "http://127.0.0.1:4780";

const statusBadge = document.querySelector("#status-badge");
const protectionButton = document.querySelector("#protection-button");
const refreshButton = document.querySelector("#refresh-button");
const eventsBody = document.querySelector("#events-body");
const allowlistBody = document.querySelector("#allowlist-body");
const eventsSearchInput = document.querySelector("#events-search");
const allowlistSearchInput = document.querySelector("#allowlist-search");

let protectionEnabled = true;
let events = [];
let allowlist = [];
let eventsSearchTerm = "";
let allowlistSearchTerm = "";

let eventsSort = {
  key: "domain",
  direction: "asc",
};

let allowlistSort = {
  key: "domain",
  direction: "asc",
};

async function apiGet(path) {
  const response = await fetch(`${API_BASE}${path}`);

  if (!response.ok) {
    throw new Error(`GET ${path} failed: ${response.status}`);
  }

  return response.json();
}

async function apiPost(path) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
  });

  if (!response.ok) {
    throw new Error(`POST ${path} failed: ${response.status}`);
  }

  return response.json();
}

function setStatus(message, isOk = true) {
  statusBadge.textContent = message;
  statusBadge.dataset.state = isOk ? "ok" : "error";
}

async function loadStatus() {
  const status = await apiGet("/status");

  protectionEnabled = status.protection_enabled;

  protectionButton.textContent = protectionEnabled
    ? "Disable Protection"
    : "Enable Protection";

  protectionButton.dataset.enabled = String(protectionEnabled);

  setStatus(
    protectionEnabled ? "Protection ON" : "Protection OFF",
    protectionEnabled
  );
}

async function loadEvents() {
  const data = await apiGet("/events?limit=50");

  events = Array.isArray(data.events) ? data.events : [];

  renderEvents();
}

function renderEvents() {
  eventsBody.innerHTML = "";

  const filteredEvents = events.filter((event) =>
    includesSearch(event.domain, eventsSearchTerm)
  );

  if (filteredEvents.length === 0) {
    eventsBody.innerHTML = `
      <tr>
        <td colspan="6" class="empty">
          ${events.length === 0 ? "No blocked events yet." : "No matching blocked domains."}
        </td>
      </tr>
    `;

    updateSortHeaders();
    return;
  }

  const sortedEvents = sortItems(filteredEvents, eventsSort, getEventSortValue);

  for (const event of sortedEvents) {
    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${escapeHtml(event.domain)}</td>
      <td>${escapeHtml(event.action)}</td>
      <td>${escapeHtml(event.matched_rule ?? "-")}</td>
      <td>${escapeHtml(event.rule_source ?? "-")}</td>
      <td>${escapeHtml(event.category ?? "-")}</td>
      <td>
        <button class="small danger" data-allow-domain="${escapeHtml(
          event.domain
        )}">
          Unblock
        </button>
      </td>
    `;

    eventsBody.appendChild(row);
  }

  updateSortHeaders();
}

async function loadAllowlist() {
  const data = await apiGet("/allowlist");

  allowlist = Array.isArray(data.allowlist) ? data.allowlist : [];

  renderAllowlist();
}

function renderAllowlist() {
  allowlistBody.innerHTML = "";

  const filteredAllowlist = allowlist.filter((domain) =>
    includesSearch(domain, allowlistSearchTerm)
  );

  if (filteredAllowlist.length === 0) {
    allowlistBody.innerHTML = `
      <tr>
        <td colspan="2" class="empty">
          ${allowlist.length === 0 ? "No allowed domains yet." : "No matching allowed domains."}
        </td>
      </tr>
    `;

    updateSortHeaders();
    return;
  }

  const sortedAllowlist = sortItems(
    filteredAllowlist,
    allowlistSort,
    (domain) => domain
  );

  for (const domain of sortedAllowlist) {
    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${escapeHtml(domain)}</td>
      <td>
        <button class="small" data-unallow-domain="${escapeHtml(domain)}">
          Block Again
        </button>
      </td>
    `;

    allowlistBody.appendChild(row);
  }

  updateSortHeaders();
}

function sortItems(items, sortState, valueGetter) {
  const direction = sortState.direction === "desc" ? -1 : 1;

  return [...items].sort((left, right) => {
    const leftValue = valueGetter(left, sortState.key);
    const rightValue = valueGetter(right, sortState.key);

    return compareValues(leftValue, rightValue) * direction;
  });
}

function getEventSortValue(event, key) {
  switch (key) {
    case "domain":
      return event.domain ?? "";
    case "action":
      return event.action ?? "";
    case "matched_rule":
      return event.matched_rule ?? "";
    case "rule_source":
      return event.rule_source ?? "";
    case "category":
      return event.category ?? "";
    default:
      return "";
  }
}

function compareValues(left, right) {
  const leftText = String(left).toLowerCase();
  const rightText = String(right).toLowerCase();

  return leftText.localeCompare(rightText);
}

function toggleEventsSort(key) {
  if (eventsSort.key === key) {
    eventsSort.direction = eventsSort.direction === "asc" ? "desc" : "asc";
  } else {
    eventsSort = {
      key,
      direction: "asc",
    };
  }

  renderEvents();
}

function toggleAllowlistSort(key) {
  if (allowlistSort.key === key) {
    allowlistSort.direction =
      allowlistSort.direction === "asc" ? "desc" : "asc";
  } else {
    allowlistSort = {
      key,
      direction: "asc",
    };
  }

  renderAllowlist();
}

function updateSortHeaders() {
  document.querySelectorAll("[data-events-sort]").forEach((header) => {
    const key = header.dataset.eventsSort;
    header.dataset.sortDirection =
      eventsSort.key === key ? eventsSort.direction : "";
  });

  document.querySelectorAll("[data-allowlist-sort]").forEach((header) => {
    const key = header.dataset.allowlistSort;
    header.dataset.sortDirection =
      allowlistSort.key === key ? allowlistSort.direction : "";
  });
}

async function refreshAll() {
  try {
    await loadStatus();
    await loadEvents();
    await loadAllowlist();
  } catch (error) {
    console.error(error);
    setStatus("API Offline", false);
  }
}

async function toggleProtection() {
  const path = protectionEnabled
    ? "/protection/disable"
    : "/protection/enable";

  await apiPost(path);
  await refreshAll();
}

async function allowDomain(domain) {
  await apiPost(`/allow?domain=${encodeURIComponent(domain)}`);
  await refreshAll();
}

async function unallowDomain(domain) {
  await apiPost(`/unallow?domain=${encodeURIComponent(domain)}`);
  await refreshAll();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function includesSearch(value, searchTerm) {
  if (!searchTerm) {
    return true;
  }

  return String(value ?? "")
    .toLowerCase()
    .includes(searchTerm.toLowerCase());
}

protectionButton.addEventListener("click", toggleProtection);
refreshButton.addEventListener("click", refreshAll);

document.addEventListener("click", async (event) => {
  const allowDomainValue = event.target.dataset.allowDomain;
  const unallowDomainValue = event.target.dataset.unallowDomain;

  if (allowDomainValue) {
    await allowDomain(allowDomainValue);
  }

  if (unallowDomainValue) {
    await unallowDomain(unallowDomainValue);
  }
});

document.querySelectorAll("[data-events-sort]").forEach((header) => {
  header.addEventListener("click", () => {
    toggleEventsSort(header.dataset.eventsSort);
  });
});

document.querySelectorAll("[data-allowlist-sort]").forEach((header) => {
  header.addEventListener("click", () => {
    toggleAllowlistSort(header.dataset.allowlistSort);
  });
});

eventsSearchInput.addEventListener("input", () => {
  eventsSearchTerm = eventsSearchInput.value.trim();
  renderEvents();
});

allowlistSearchInput.addEventListener("input", () => {
  allowlistSearchTerm = allowlistSearchInput.value.trim();
  renderAllowlist();
});

refreshAll();
setInterval(refreshAll, 3000);