const adblockList = document.querySelector("#adblock-list");
const clearUnblockedButton = document.querySelector("#clear-unblocked-button");
const addDomainForm = document.querySelector("#add-domain-form");
const addDomainInput = document.querySelector("#add-domain-input");
const addDomainMessage = document.querySelector("#add-domain-message");
const tabButtons = document.querySelectorAll("[data-adblock-tab]");

const expandedDomains = new Set();

let activeTab = "Ad";

function sendMessage(message) {
  return chrome.runtime.sendMessage(message);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatTime(value) {
  if (!value) {
    return "-";
  }

  return new Date(value).toLocaleString();
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

function showAddDomainMessage(message, isError = false) {
  addDomainMessage.textContent = message;
  addDomainMessage.dataset.state = isError ? "error" : "ok";
  addDomainMessage.classList.remove("hidden");
}

function clearAddDomainMessage() {
  addDomainMessage.textContent = "";
  addDomainMessage.classList.add("hidden");
}

function storedDomain(value) {
  if (typeof value === "string") {
    return value.toLowerCase();
  }

  if (value && typeof value === "object") {
    return String(value.domain ?? "").toLowerCase();
  }

  return "";
}

function storedDetectionType(value) {
  if (value && typeof value === "object") {
    return value.detectionType || "Ad";
  }

  return "Ad";
}

async function loadState() {
  const response = await sendMessage({
    type: "GET_STATE",
  });

  if (!response.ok) {
    throw new Error(response.error || "Failed to load state");
  }

  renderAdblockDomains({
    blockedDomains: response.blockedDomains ?? [],
    ignoredDomains: response.ignoredDomains ?? [],
    candidates: response.candidates ?? [],
  });
}

function buildAdblockRows({ blockedDomains, ignoredDomains, candidates }) {
  const rowsByDomain = new Map();

  for (const ignored of ignoredDomains) {
    const domain = storedDomain(ignored);

    if (!domain) {
      continue;
    }

    rowsByDomain.set(domain, {
      domain,
      blocked: false,
      status: "Unblocked",
      detectionType: storedDetectionType(ignored),
      reason:
        typeof ignored === "object" && ignored.reason
          ? ignored.reason
          : "This domain is currently unblocked or ignored.",
      requestType:
        typeof ignored === "object" && ignored.requestType
          ? ignored.requestType
          : "manual",
      source:
        typeof ignored === "object" && ignored.source
          ? ignored.source
          : "user",
      url:
        typeof ignored === "object" && ignored.url
          ? ignored.url
          : "",
      lastSeenAt:
        typeof ignored === "object" && ignored.createdAt
          ? ignored.createdAt
          : null,
      count:
        typeof ignored === "object" && ignored.count
          ? ignored.count
          : 0,
    });
  }

  for (const candidate of candidates) {
    const domain = storedDomain(candidate);

    if (!domain || rowsByDomain.has(domain)) {
      continue;
    }

    rowsByDomain.set(domain, {
      domain,
      blocked: false,
      status: "Pending",
      detectionType: candidate.detectionType || "Ad",
      reason: candidate.reason || "Possible ad/tracker domain.",
      requestType: candidate.requestType || "unknown",
      source: candidate.source || "browser",
      url: candidate.url || "",
      lastSeenAt: candidate.lastSeenAt,
      count: candidate.count ?? 1,
    });
  }

  for (const blocked of blockedDomains) {
    const domain = storedDomain(blocked);

    if (!domain) {
      continue;
    }

    rowsByDomain.set(domain, {
      domain,
      blocked: true,
      status: "Blocked",
      detectionType: blocked.detectionType || "Ad",
      reason:
        blocked.reason ||
        "This domain was blocked because it matched an ad/tracker pattern or was manually added.",
      requestType: blocked.requestType || "manual",
      source: blocked.source || "browser",
      url: blocked.url || "",
      lastSeenAt: blocked.createdAt,
      count: blocked.count ?? 1,
    });
  }

  return Array.from(rowsByDomain.values())
    .filter((row) => row.detectionType === activeTab)
    .sort((left, right) => {
      if (left.blocked !== right.blocked) {
        return left.blocked ? 1 : -1;
      }

      return left.domain.localeCompare(right.domain);
    });
}

function renderTabs() {
  tabButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.adblockTab === activeTab);
  });
}

function renderAdblockDomains(state) {
  renderTabs();

  adblockList.innerHTML = "";

  const rows = buildAdblockRows(state);

  if (!rows.length) {
    adblockList.innerHTML = `
      <div class="empty">
        No ${activeTab.toLowerCase()} domains detected yet.
      </div>
    `;
    return;
  }

  for (const row of rows) {
    const item = document.createElement("div");
    item.className = "item adblock-row";

    const isExpanded = expandedDomains.has(row.domain);

    item.innerHTML = `
      <div class="domain-main" data-expand-domain="${escapeHtml(row.domain)}">
        <div class="domain-line">
          <div class="domain">${escapeHtml(row.domain)}</div>
          <span class="expand-indicator">${isExpanded ? "▾" : "▸"}</span>
        </div>

        <div class="meta">
          ${escapeHtml(row.status)}
          ${
            row.lastSeenAt
              ? ` · ${escapeHtml(formatTime(row.lastSeenAt))}`
              : ""
          }
        </div>
      </div>

      <label class="switch" title="${row.blocked ? "Blocked" : "Unblocked"}">
        <input
          type="checkbox"
          data-adblock-switch="${escapeHtml(row.domain)}"
          data-adblock-type="${escapeHtml(row.detectionType)}"
          ${row.blocked ? "checked" : ""}
        />
        <span class="slider"></span>
      </label>

      ${
        isExpanded
          ? `
            <div class="domain-details">
              <div>
                <span>Reason</span>
                <p>${escapeHtml(row.reason)}</p>
              </div>

              <div class="detail-grid">
                <div>
                  <span>Browser Request</span>
                  <p>${escapeHtml(row.requestType)}</p>
                </div>

                <div>
                  <span>Source</span>
                  <p>${escapeHtml(row.source)}</p>
                </div>

                <div>
                  <span>Seen</span>
                  <p>${escapeHtml(row.count || 0)} time(s)</p>
                </div>
              </div>

              ${
                row.url
                  ? `
                    <div>
                      <span>Request URL</span>
                      <p>${escapeHtml(row.url)}</p>
                    </div>
                  `
                  : ""
              }
            </div>
          `
          : ""
      }
    `;

    adblockList.appendChild(item);
  }
}

function classifyDomain(domain) {
  const normalizedDomain = String(domain ?? "").toLowerCase();
  const labels = normalizedDomain.split(".");

  const trackerLabels = new Set([
    "analytics",
    "tracker",
    "tracking",
    "pixel",
    "beacon",
    "metrics",
    "telemetry",
  ]);

  const adLabels = new Set([
    "ad",
    "ads",
    "adserver",
    "adservice",
    "adservices",
  ]);

  const trackerDomainParts = [
    "scorecardresearch",
    "quantserve",
    "analytics",
    "tracking",
    "tracker",
    "pixel",
    "beacon",
    "metrics",
    "telemetry",
    "google-analytics",
    "googletagmanager",
    "facebook.com",
    "connect.facebook",
    "hotjar",
    "segment",
    "mixpanel",
    "amplitude",
    "fullstory",
    "clarity",
    "newrelic",
    "nr-data",
    "tiktok",
    "twitter",
    "linkedin",
    "licdn",
    "pinterest",
    "reddit",
  ];

  const adDomainParts = [
    "doubleclick",
    "googlesyndication",
    "googleadservices",
    "adnxs",
    "adsystem",
    "adform",
    "taboola",
    "outbrain",
    "popads",
    "popcash",
  ];

  if (labels.some((label) => trackerLabels.has(label))) {
    return {
      detectionType: "Tracker",
      reason:
        "This domain contains a label commonly used by tracking or analytics services.",
    };
  }

  if (trackerDomainParts.some((part) => normalizedDomain.includes(part))) {
    return {
      detectionType: "Tracker",
      reason:
        "This domain matches a common tracker or analytics network pattern.",
    };
  }

  if (labels.some((label) => adLabels.has(label))) {
    return {
      detectionType: "Ad",
      reason:
        "This domain contains a label commonly used by ad delivery services.",
    };
  }

  if (adDomainParts.some((part) => normalizedDomain.includes(part))) {
    return {
      detectionType: "Ad",
      reason:
        "This domain matches a common ad network pattern.",
    };
  }

  return null;
}

tabButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    activeTab = button.dataset.adblockTab;
    expandedDomains.clear();
    await loadState();
  });
});

addDomainForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  clearAddDomainMessage();

  const domain = normalizeDomainInput(addDomainInput.value);
  const validationError = validateDomainName(domain);

  if (validationError) {
    showAddDomainMessage(validationError, true);
    return;
  }

  const classification = classifyDomain(domain);

  if (!classification) {
    showAddDomainMessage(
      "This domain is not an ad or tracker.",
      true
    );
    return;
  }

  try {
    await sendMessage({
      type: "BLOCK_DOMAIN",
      domain,
      detectionType: classification.detectionType,
      reason: classification.reason,
      requestType: "manual",
      source: "user",
    });

    activeTab = classification.detectionType;
    await loadState();

    addDomainInput.value = "";

    showAddDomainMessage(
      `${domain} added to ${classification.detectionType.toLowerCase()} domains.`
    );
  } catch (error) {
    showAddDomainMessage(error.message || "Failed to add domain.", true);
  }
});

document.addEventListener("click", async (event) => {
  const expandTarget = event.target.closest("[data-expand-domain]");

  if (!expandTarget) {
    return;
  }

  const domain = expandTarget.dataset.expandDomain;

  if (expandedDomains.has(domain)) {
    expandedDomains.delete(domain);
  } else {
    expandedDomains.add(domain);
  }

  await loadState();
});

document.addEventListener("change", async (event) => {
  const switchInput = event.target.closest("[data-adblock-switch]");

  if (!switchInput) {
    return;
  }

  const domain = switchInput.dataset.adblockSwitch;
  const detectionType = switchInput.dataset.adblockType || activeTab;

  switchInput.disabled = true;

  try {
    if (switchInput.checked) {
      await sendMessage({
        type: "BLOCK_DOMAIN",
        domain,
        detectionType,
        reason: `This domain was manually blocked as a ${detectionType.toLowerCase()} domain.`,
        requestType: "manual",
        source: "user",
      });
    } else {
      await sendMessage({
        type: "UNBLOCK_DOMAIN",
        domain,
      });
    }

    await loadState();
  } catch (error) {
    console.error(error);
    switchInput.checked = !switchInput.checked;
  } finally {
    switchInput.disabled = false;
  }
});

clearUnblockedButton.addEventListener("click", async () => {
  await sendMessage({
    type: "CLEAR_UNBLOCKED",
    detectionType: activeTab,
  });

  expandedDomains.clear();
  await loadState();
});

loadState().catch((error) => {
  adblockList.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
});