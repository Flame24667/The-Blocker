import "./styles.css";

const API_BASE = "http://127.0.0.1:4780";

const statusBadge = document.querySelector("#status-badge");
const protectionButton = document.querySelector("#protection-button");
const addDomainButton = document.querySelector("#add-domain-button");
const eventsBody = document.querySelector("#events-body");
const allowlistBody = document.querySelector("#allowlist-body");
const eventsSearchInput = document.querySelector("#events-search");
const allowlistSearchInput = document.querySelector("#allowlist-search");
const addDomainModal = document.querySelector("#add-domain-modal");
const closeAddDomainModal = document.querySelector("#close-add-domain-modal");
const cancelAddDomainButton = document.querySelector("#cancel-add-domain-button");
const addDomainForm = document.querySelector("#add-domain-form");
const addDomainInput = document.querySelector("#add-domain-input");
const addDomainError = document.querySelector("#add-domain-error");

let protectionEnabled = true;
let events = [];
let allowlist = [];
let eventsSearchTerm = "";
let allowlistSearchTerm = "";
let blocklist = [];

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
  const data = await apiGet("/blocked-domains?limit=50");

  events = Array.isArray(data.events) ? data.events : [];

  renderEvents();
}

function renderEvents() {
  eventsBody.innerHTML = "";

  const allowedDomains = new Set(allowlist.map((domain) => domain.toLowerCase()));
  const eventDomainMap = new Map();

  for (const event of events) {
    const domain = String(event.domain ?? "").toLowerCase();

    if (!domain || allowedDomains.has(domain)) {
      continue;
    }

    eventDomainMap.set(domain, event);
  }

  for (const domain of blocklist) {
    const normalizedDomain = String(domain ?? "").toLowerCase();

    if (!normalizedDomain || allowedDomains.has(normalizedDomain)) {
      continue;
    }

    if (!eventDomainMap.has(normalizedDomain)) {
      eventDomainMap.set(normalizedDomain, {
        domain,
        block_count: 0,
        last_blocked_at_unix: 0,
        matched_rule: domain,
        rule_source: "user-blocklist",
        category: "manual",
      });
    }
  }

  const blockedRows = Array.from(eventDomainMap.values());

  const filteredEvents = blockedRows.filter((event) =>
    includesSearch(event.domain, eventsSearchTerm)
  );

  if (filteredEvents.length === 0) {
    eventsBody.innerHTML = `
      <tr>
        <td colspan="7" class="empty">
          ${blockedRows.length === 0 ? "No blocked domains yet." : "No matching blocked domains."}
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
      <td>${escapeHtml(event.block_count ?? 0)}</td>
      <td>${escapeHtml(formatUnixTime(event.last_blocked_at_unix))}</td>
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

async function loadBlocklist() {
  const data = await apiGet("/blocklist");

  blocklist = Array.isArray(data.blocklist) ? data.blocklist : [];
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
        <div class="row-actions">
          <button class="small danger" data-block-again-domain="${escapeHtml(domain)}">
            Block
          </button>

          <button class="small" data-delete-allowed-domain="${escapeHtml(domain)}">
            Delete
          </button>
        </div>
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
    case "block_count":
      return Number(event.block_count ?? 0);
    case "last_blocked_at_unix":
      return Number(event.last_blocked_at_unix ?? 0);
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
  if (typeof left === "number" && typeof right === "number") {
    return left - right;
  }

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

async function loadDashboard() {
  try {
    await loadStatus();
    await loadAllowlist();
    await loadBlocklist();
    await loadEvents();
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
  await loadDashboard();
}

async function allowDomain(domain) {
  await apiPost(`/allow?domain=${encodeURIComponent(domain)}`);
  await loadDashboard();
}

async function unallowDomain(domain) {
  await apiPost(`/unallow?domain=${encodeURIComponent(domain)}`);
  await loadDashboard();
}

function formatUnixTime(value) {
  const seconds = Number(value);

  if(!Number.isFinite(seconds) || seconds <= 0) {
    return "-";
  }

  return new Date(seconds *1000).toLocaleString();
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

function openAddDomainModal() {
  addDomainModal.classList.remove("hidden");
  addDomainInput.value = "";
  clearAddDomainError();
  addDomainInput.focus();
}

function closeAddDomainModalView() {
  addDomainModal.classList.add("hidden");
  clearAddDomainError();
}

async function submitAddDomain(event) {
  event.preventDefault();

  clearAddDomainError();

  const domain = normalizeDomainInput(addDomainInput.value);
  const validationError = validateDomainName(domain);

  if (validationError) {
    showAddDomainError(validationError);
    return;
  }

  const hasEvidence = hasAdOrTrackerEvidence(domain);

  if (!hasEvidence) {
    showAddDomainError(
      "This is a valid domain, but The Blocker has not detected it as an ad/tracker domain yet. Add it only if you trust this manual rule."
    );
  }

  await apiPost(`/blocklist/add?domain=${encodeURIComponent(domain)}`);

  closeAddDomainModalView();
  await loadDashboard();
}

async function unblockDomain(domain) {
  await apiPost(`/allow?domain=${encodeURIComponent(domain)}`);
  await loadDashboard();
}

async function blockAgainDomain(domain) {
  await apiPost(`/blocklist/add?domain=${encodeURIComponent(domain)}`);
  await loadDashboard();
}

async function deleteAllowedDomain(domain) {
  await apiPost(`/unallow?domain=${encodeURIComponent(domain)}`);
  await loadDashboard();
}

function normalizeDomainInput(value) {
  let text = String(value ?? "").trim().toLowerCase();

  if (!text) {
    return "";
  }

  if (text.includes("://")) {
    try {
      text = new URL(text).hostname;
    } catch {
      return text;
    }
  }

  text = text.split("/")[0];
  text = text.split("?")[0];
  text = text.split("#")[0];
  text = text.replace(/\.$/, "");

  return text;
}

function validateDomainName(domain) {
  if (!domain) {
    return "Please enter a domain.";
  }

  if (domain.length > 253) {
    return "Domain is too long.";
  }

  if (domain.includes(" ")) {
    return "Domain cannot contain spaces.";
  }

  if (domain.includes("_")) {
    return "Domain cannot contain underscores.";
  }

  if (!domain.includes(".")) {
    return "Enter a full domain, for example example.com.";
  }

  const labels = domain.split(".");

  for (const label of labels) {
    if (!label) {
      return "Domain has an empty section.";
    }

    if (label.length > 63) {
      return "One part of the domain is too long.";
    }

    if (label.startsWith("-") || label.endsWith("-")) {
      return "Domain sections cannot start or end with a dash.";
    }

    if (!/^[a-z0-9-]+$/.test(label)) {
      return "Domain can only contain letters, numbers, dots, and dashes.";
    }
  }

  return "";
}

function hasAdOrTrackerEvidence(domain) {
  const normalizedDomain = domain.toLowerCase();

  const appearsInBlockedEvents = events.some((event) => {
    return String(event.domain ?? "").toLowerCase() === normalizedDomain;
  });

  const appearsInBlocklist = blocklist.some((blockedDomain) => {
    return String(blockedDomain ?? "").toLowerCase() === normalizedDomain;
  });

  return appearsInBlockedEvents || appearsInBlocklist;
}

function showAddDomainError(message) {
  addDomainError.textContent = message;
  addDomainError.classList.remove("hidden");
}

function clearAddDomainError() {
  addDomainError.textContent = "";
  addDomainError.classList.add("hidden");
}

protectionButton.addEventListener("click", toggleProtection);

addDomainButton.addEventListener("click", openAddDomainModal);
addDomainForm.addEventListener("submit", submitAddDomain);
closeAddDomainModal.addEventListener("click", closeAddDomainModalView);
cancelAddDomainButton.addEventListener("click", closeAddDomainModalView);

addDomainModal.addEventListener("click", (event) => {
  if (event.target === addDomainModal) {
    closeAddDomainModalView();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !addDomainModal.classList.contains("hidden")) {
    closeAddDomainModalView();
  }
});

eventsBody.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-allow-domain]");

  if (!button) {
    return;
  }

  await unblockDomain(button.dataset.allowDomain);
});

allowlistBody.addEventListener("click", async (event) => {
  const blockAgainButton = event.target.closest("[data-block-again-domain]");
  const deleteButton = event.target.closest("[data-delete-allowed-domain]");

  if (blockAgainButton) {
    await blockAgainDomain(blockAgainButton.dataset.blockAgainDomain);
    return;
  }

  if (deleteButton) {
    await deleteAllowedDomain(deleteButton.dataset.deleteAllowedDomain);
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

loadDashboard();