const MAX_CANDIDATES = 100;
const DESKTOP_API_BASE = "http://127.0.0.1:4780";
const DESKTOP_API_TIMEOUT_MS = 1000;
const DESKTOP_SYNC_ALARM = "the-blocker-desktop-sync";
const DESKTOP_SYNC_PERIOD_MINUTES = 1;
const BLOCKED_RESPONSE_URL = `${DESKTOP_API_BASE}/blocked-response`;

const RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "stylesheet",
  "script",
  "image",
  "font",
  "object",
  "xmlhttprequest",
  "ping",
  "media",
  "websocket",
  "other",
];

const BLOCK_RESOURCE_TYPES = RESOURCE_TYPES.filter(
  (type) => type !== "main_frame"
);

const suspiciousExactLabels = new Set([
  "ad",
  "ads",
  "adserver",
  "adservice",
  "adservices",
  "analytics",
  "tracker",
  "tracking",
  "pixel",
  "beacon",
  "metrics",
  "telemetry",
]);

const suspiciousDomainParts = [
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
  "scorecardresearch",
  "quantserve",
];

function normalizeDomainFromUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "";
  }
}

function validateDomainName(domain) {
  if (!domain) {
    return false;
  }

  if (domain.length > 253) {
    return false;
  }

  if (!domain.includes(".")) {
    return false;
  }

  const labels = domain.split(".");

  for (const label of labels) {
    if (!label || label.length > 63) {
      return false;
    }

    if (label.startsWith("-") || label.endsWith("-")) {
      return false;
    }

    if (!/^[a-z0-9-]+$/.test(label)) {
      return false;
    }
  }

  return true;
}

function classifyPossibleAdDomain(domain, requestType) {
  const labels = domain.split(".");

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
      type: "Tracker",
      reason:
        "The domain contains a label commonly used by tracking or analytics services.",
    };
  }

  if (trackerDomainParts.some((part) => domain.includes(part))) {
    return {
      type: "Tracker",
      reason:
        "The domain name matches a common tracker or analytics network pattern.",
    };
  }

  if (labels.some((label) => adLabels.has(label))) {
    return {
      type: "Ad",
      reason:
        "The domain contains a label commonly used by ad delivery services.",
    };
  }

  if (adDomainParts.some((part) => domain.includes(part))) {
    return {
      type: "Ad",
      reason:
        "The domain name matches a common ad network pattern.",
    };
  }

  return null;
}

async function getLocalState() {
  const state = await chrome.storage.local.get({
    candidates: [],
    blockedDomains: [],
    ignoredDomains: [],
    nextRuleId: 1000,
  });

  return state;
}

async function setLocalState(partialState) {
  await chrome.storage.local.set(partialState);
}

async function updateBadge() {
  const { candidates } = await getLocalState();

  if (candidates.length === 0) {
    await chrome.action.setBadgeText({ text: "" });
    return;
  }

  await chrome.action.setBadgeText({
    text: String(Math.min(candidates.length, 99)),
  });

  await chrome.action.setBadgeBackgroundColor({
    color: "#f59e0b",
  });
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

function sameDomain(left, right) {
  return storedDomain(left) === storedDomain(right);
}

async function recordCandidate(candidate, tabId) {
  const state = await getLocalState();

  const domain = candidate.domain.toLowerCase();

  if (state.blockedDomains.some((item) => sameDomain(item.domain, domain))) {
    return;
  }

  if (state.ignoredDomains.some((item) => sameDomain(item, domain))) {
    return;
  }

  await blockDomain(domain, candidate);
}

function classifyManualDomainType(domain) {
  const classification = classifyPossibleAdDomain(domain, "manual");

  if (classification) {
    return classification.type;
  }

  return "Ad";
}

async function blockDomain(domain, metadata = {}, options = {}) {
  const normalizedDomain = String(domain ?? "").toLowerCase();

  if (!validateDomainName(normalizedDomain)) {
    throw new Error("Invalid domain");
  }

  const state = await getLocalState();

  const detectionType =
  metadata.detectionType || classifyManualDomainType(normalizedDomain);

  const existingBlockedDomain = state.blockedDomains.find((item) =>
    sameDomain(item.domain, normalizedDomain)
  );

  if (existingBlockedDomain) {
    const blockedDomains = state.blockedDomains.map((item) => {
      if (!sameDomain(item.domain, normalizedDomain)) {
        return item;
      }

      return {
        ...item,
        detectionType,
        reason:
          metadata.reason ||
          item.reason ||
          "This domain was manually added or matched an ad/tracker pattern.",
        requestType: metadata.requestType || item.requestType || "manual",
        source: metadata.source || item.source || "user",
        url: metadata.url || item.url || "",
        count: item.count || metadata.count || 1,
      };
    });

    const candidates = state.candidates.filter(
      (item) => !sameDomain(item.domain, normalizedDomain)
    );

    const ignoredDomains = state.ignoredDomains.filter(
      (item) => !sameDomain(item, normalizedDomain)
    );

    await setLocalState({
      blockedDomains,
      candidates,
      ignoredDomains,
    });

    await updateBadge();
    if (!options.skipDesktopSync) {
      await syncBlockedDomainToDesktop(normalizedDomain);
    }
    return;
  }

  const ruleId = state.nextRuleId;

  const rule = {
    id: ruleId,
    priority: 1,
    action: {
      type: "redirect",
      redirect: {
        url: `${BLOCKED_RESPONSE_URL}?domain=${encodeURIComponent(normalizedDomain)}`,
      },
    },
    condition: {
      urlFilter: `||${normalizedDomain}^`,
      resourceTypes: BLOCK_RESOURCE_TYPES,
    },
  };

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [ruleId],
    addRules: [rule],
  });

  const candidates = state.candidates.filter(
    (item) => !sameDomain(item.domain, normalizedDomain)
  );

  const ignoredDomains = state.ignoredDomains.filter(
    (item) => !sameDomain(item, normalizedDomain)
  );

  const blockedDomains = [
    ...state.blockedDomains,
    {
      domain: normalizedDomain,
      ruleId,
      createdAt: Date.now(),
      detectionType,
      reason:
        metadata.reason ||
        "This domain was manually added or matched an ad/tracker pattern.",
      requestType: metadata.requestType || "manual",
      source: metadata.source || "manual",
      url: metadata.url || "",
      count: metadata.count || 1,
    },
  ];

  await setLocalState({
    candidates,
    ignoredDomains,
    blockedDomains,
    nextRuleId: ruleId + 1,
  });

  await updateBadge();
  if (!options.skipDesktopSync) {
    await syncBlockedDomainToDesktop(normalizedDomain);
  }
}

async function unblockDomain(domain, options = {}) {
  const normalizedDomain = String(domain ?? "").toLowerCase();
  const state = await getLocalState();

  const rule = state.blockedDomains.find((item) =>
    sameDomain(item.domain, normalizedDomain)
  );

  if (!rule) {
    return;
  }

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [rule.ruleId],
  });

  const ignoredRecord = {
    domain: normalizedDomain,
    detectionType: rule.detectionType || "Ad",
    reason: rule.reason || "This domain was blocked by the user.",
    requestType: rule.requestType || "manual",
    source: rule.source || "manual",
    url: rule.url || "",
    count: rule.count || 1,
    createdAt: Date.now(),
  };

  const ignoredDomains = [
    ...state.ignoredDomains.filter((item) => !sameDomain(item, normalizedDomain)),
    ignoredRecord,
  ];

  await setLocalState({
    blockedDomains: state.blockedDomains.filter(
      (item) => !sameDomain(item.domain, normalizedDomain)
    ),
    ignoredDomains,
  });

  await updateBadge();
  if (!options.skipDesktopSync) {
    await syncAllowedDomainToDesktop(normalizedDomain);
  }
}

async function ignoreDomain(domain, metadata = {}, options = {}) {
  const normalizedDomain = String(domain ?? "").toLowerCase();
  const state = await getLocalState();

  const candidates = state.candidates.filter(
    (item) => !sameDomain(item.domain, normalizedDomain)
  );

  const ignoredRecord = {
    domain: normalizedDomain,
    detectionType: metadata.detectionType || "Ad",
    reason: metadata.reason || "This domain was ignored by the user.",
    requestType: metadata.requestType || "manual",
    source: metadata.source || "manual",
    url: metadata.url || "",
    count: metadata.count || 1,
    createdAt: Date.now(),
  };

  const ignoredDomains = [
    ...state.ignoredDomains.filter((item) => !sameDomain(item, normalizedDomain)),
    ignoredRecord,
  ];

  await setLocalState({
    candidates,
    ignoredDomains,
  });

  await updateBadge();
  if (!options.skipDesktopSync) {
    await syncAllowedDomainToDesktop(normalizedDomain);
  }
}

async function clearUnblockedDomains(detectionType, options = {}) {
  const state = await getLocalState();
  const removedDomains = [];

  const filteredIgnoredDomains = state.ignoredDomains.filter((item) => {
    if (storedDetectionType(item) === detectionType) {
      const domain = storedDomain(item);

      if (domain) {
        removedDomains.push(domain);
      }

      return false;
    }

    return true;
  });

  await setLocalState({
    ignoredDomains: filteredIgnoredDomains,
  });

  if (!options.skipDesktopSync) {
    await Promise.all(
      removedDomains.map((domain) => syncUnallowDomainToDesktop(domain))
    );
  }

  await updateBadge();
}

async function rebuildUserDynamicRulesWithoutMainFrame() {
  const state = await getLocalState();

  const removeRuleIds = state.blockedDomains
    .map((item) => item.ruleId)
    .filter((ruleId) => Number.isInteger(ruleId));

  const addRules = state.blockedDomains
    .filter((item) => validateDomainName(item.domain))
    .map((item) => ({
      id: item.ruleId,
      priority: 1,
      action: {
        type: "redirect",
        redirect: {
          url: `${BLOCKED_RESPONSE_URL}?domain=${encodeURIComponent(item.domain)}`,
        },
      },
      condition: {
        urlFilter: `||${item.domain}^`,
        resourceTypes: BLOCK_RESOURCE_TYPES,
      },
    }));

  if (removeRuleIds.length === 0 && addRules.length === 0) {
    return;
  }

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules,
  });
}

// Sync
async function desktopApiRequest(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DESKTOP_API_TIMEOUT_MS);

  try {
    const response = await fetch(`${DESKTOP_API_BASE}${path}`, {
      method: options.method || "GET",
      signal: controller.signal,
    });

    await chrome.storage.local.set({
      desktopBridge: {
        connected: response.ok,
        status: response.status,
        lastCheckedAt: Date.now(),
      },
    });

    if (!response.ok) {
      return null;
    }

    return response;
  } catch (error) {
    await chrome.storage.local.set({
      desktopBridge: {
        connected: false,
        error: error.message || "Desktop API offline",
        lastCheckedAt: Date.now(),
      },
    });

    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function desktopApiJson(path) {
  const response = await desktopApiRequest(path);

  if (!response) {
    return null;
  }

  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function syncBlockedDomainToDesktop(domain) {
  await desktopApiRequest(
    `/blocklist/add?domain=${encodeURIComponent(domain)}`,
    { method: "POST" }
  );
}

async function syncAllowedDomainToDesktop(domain) {
  await desktopApiRequest(
    `/allow?domain=${encodeURIComponent(domain)}`,
    { method: "POST" }
  );
}

async function syncUnallowDomainToDesktop(domain) {
  await desktopApiRequest(
    `/unallow?domain=${encodeURIComponent(domain)}`,
    { method: "POST" }
  );
}

function extractDomainList(payload, key) {
  if (!payload || !Array.isArray(payload[key])) {
    return [];
  }

  return payload[key]
    .map((domain) => String(domain ?? "").toLowerCase())
    .filter((domain) => validateDomainName(domain));
}

async function syncFromDesktopApp() {
  const [blocklistPayload, allowlistPayload] = await Promise.all([
    desktopApiJson("/blocklist"),
    desktopApiJson("/allowlist"),
  ]);

  if (!blocklistPayload && !allowlistPayload) {
    return;
  }

  const desktopBlocklist = extractDomainList(blocklistPayload, "blocklist");
  const desktopAllowlist = extractDomainList(allowlistPayload, "allowlist");
  const allowedDomains = new Set(desktopAllowlist);

  for (const domain of desktopAllowlist) {
    await unblockDomain(domain, {
      skipDesktopSync: true,
    });
  }

  for (const domain of desktopBlocklist) {
    if (allowedDomains.has(domain)) {
      continue;
    }

    await blockDomain(
      domain,
      {
        detectionType: classifyManualDomainType(domain),
        reason: "Synced from The Blocker desktop app.",
        requestType: "desktop-sync",
        source: "desktop-app",
      },
      {
        skipDesktopSync: true,
      }
    );
  }

  await updateBadge();
}

async function syncExtensionStateToDesktopApp() {
  const state = await getLocalState();

  const blockedDomains = state.blockedDomains
    .map((item) => storedDomain(item))
    .filter((domain) => validateDomainName(domain));

  const ignoredDomains = state.ignoredDomains
    .map((item) => storedDomain(item))
    .filter((domain) => validateDomainName(domain));

  for (const domain of blockedDomains) {
    await syncBlockedDomainToDesktop(domain);
  }

  for (const domain of ignoredDomains) {
    await syncAllowedDomainToDesktop(domain);
  }
}

// turtlecute
const TURTLECUTE_ADBLOCK_LIST_URL =
  "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.adblock";

const TURTLECUTE_RULE_ID_START = 200000;
const TURTLECUTE_RULE_ID_LIMIT = 500;

function parseAdblockHostDomains(text) {
  const domains = new Set();
  const pattern = /\|\|([a-z0-9.-]+)\^/gi;

  let match;

  while ((match = pattern.exec(text)) !== null) {
    const domain = String(match[1] ?? "").toLowerCase();

    if (validateDomainName(domain)) {
      domains.add(domain);
    }
  }

  return Array.from(domains);
}

async function installTurtlecuteHostRules() {
  const response = await fetch(TURTLECUTE_ADBLOCK_LIST_URL);

  if (!response.ok) {
    throw new Error(`Failed to fetch Turtlecute host list: ${response.status}`);
  }

  const text = await response.text();
  const domains = parseAdblockHostDomains(text).slice(0, TURTLECUTE_RULE_ID_LIMIT);

  const removeRuleIds = Array.from(
    { length: TURTLECUTE_RULE_ID_LIMIT },
    (_, index) => TURTLECUTE_RULE_ID_START + index
  );

  const addRules = domains.map((domain, index) => ({
    id: TURTLECUTE_RULE_ID_START + index,
    priority: 5,
    action: {
      type: "block",
    },
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes: BLOCK_RESOURCE_TYPES,
    },
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules,
  });

  await chrome.storage.local.set({
    turtlecuteHostRulesInstalledAt: Date.now(),
    turtlecuteHostRulesCount: addRules.length,
  });

  console.log(`Installed ${addRules.length} Turtlecute host rules.`);
}

// chrome check sections

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const domain = normalizeDomainFromUrl(details.url);

    if (!validateDomainName(domain)) {
      return;
    }

    const classification = classifyPossibleAdDomain(domain, details.type);

    if (!classification) {
      return;
    }

    recordCandidate(
      {
        domain,
        url: details.url,
        pageUrl: details.initiator || details.documentUrl || "",
        reason: classification.reason,
        detectionType: classification.type,
        requestType: details.type,
        source: "webRequest",
      },
      details.tabId
    );
  },
  {
    urls: ["<all_urls>"],
  }
);

chrome.webNavigation.onCreatedNavigationTarget.addListener((details) => {
  const domain = normalizeDomainFromUrl(details.url);

  if (!validateDomainName(domain)) {
    return;
  }

  const classification = classifyPossibleAdDomain(domain, "popup/new-tab");

  if (!classification) {
    return;
  }

  recordCandidate(
    {
      domain,
      url: details.url,
      pageUrl: "",
      reason: `${classification.reason} A new browser target was opened.`,
      detectionType: classification.type,
      requestType: "popup/new-tab",
      source: "webNavigation",
    },
    details.tabId
  );
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  async function handleMessage() {
    if (message.type === "GET_STATE") {
      await syncExtensionStateToDesktopApp();
      await syncFromDesktopApp();

      const state = await getLocalState();
      const bridgeState = await chrome.storage.local.get({
        desktopBridge: null,
      });

      sendResponse({
        ok: true,
        candidates: state.candidates,
        ignoredDomains: state.ignoredDomains,
        blockedDomains: state.blockedDomains,
        desktopBridge: bridgeState.desktopBridge,
      });

      return;
    }

    if (message.type === "BLOCK_DOMAIN") {
      await blockDomain(message.domain, {
        detectionType: message.detectionType,
        reason: message.reason || "This domain was manually added by the user.",
        requestType: message.requestType || "manual",
        source: message.source || "user",
        url: message.url || "",
      });

      sendResponse({ ok: true });
      return;
    }

    if (message.type === "UNBLOCK_DOMAIN") {
      await unblockDomain(message.domain);
      sendResponse({ ok: true });
      return;
    }

    if (message.type === "IGNORE_DOMAIN") {
      await ignoreDomain(message.domain, {
        detectionType: message.detectionType,
        reason: message.reason,
        requestType: message.requestType,
        source: message.source,
        url: message.url,
      });

      sendResponse({ ok: true });
      return;
    }

    if (message.type === "CLEAR_CANDIDATES") {
      await setLocalState({ candidates: [] });
      await updateBadge();
      sendResponse({ ok: true });
      return;
    }

    if (message.type === "CLEAR_UNBLOCKED") {
      await clearUnblockedDomains(message.detectionType || "Ad");
      sendResponse({ ok: true });
      return;
    }

    sendResponse({ ok: false, error: "Unknown message type" });
  }

  handleMessage().catch((error) => {
    sendResponse({
      ok: false,
      error: String(error),
    });
  });

  return true;
});

// startup
async function startup() {
  await Promise.all([
    rebuildUserDynamicRulesWithoutMainFrame(),
    installTurtlecuteHostRules(),
  ]);

  await syncExtensionStateToDesktopApp();
  await syncFromDesktopApp();
  await updateBadge();

  await chrome.alarms.create(DESKTOP_SYNC_ALARM, {
    periodInMinutes: DESKTOP_SYNC_PERIOD_MINUTES,
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(DESKTOP_SYNC_ALARM, {
    periodInMinutes: DESKTOP_SYNC_PERIOD_MINUTES,
  });
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(DESKTOP_SYNC_ALARM, {
    periodInMinutes: DESKTOP_SYNC_PERIOD_MINUTES,
  });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== DESKTOP_SYNC_ALARM) {
    return;
  }

  syncFromDesktopApp().catch((error) => {
    console.error("Desktop sync failed:", error);
  });
});

startup().catch((error) => {
  console.error("Extension startup failed:", error);
});