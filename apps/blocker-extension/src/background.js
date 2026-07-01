const MAX_CANDIDATES = 100;

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

async function blockDomain(domain, metadata = {}) {
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
    return;
  }

  const ruleId = state.nextRuleId;

  const rule = {
    id: ruleId,
    priority: 1,
    action: {
      type: "block",
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
}

async function unblockDomain(domain) {
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
}

async function ignoreDomain(domain, metadata = {}) {
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
}

async function clearUnblockedDomains(detectionType) {
  const state = await getLocalState();

  const filteredIgnoredDomains = state.ignoredDomains.filter((item) => {
    return storedDetectionType(item) !== detectionType;
  });

  await setLocalState({
    ignoredDomains: filteredIgnoredDomains,
  });

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
        type: "block",
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
      const state = await getLocalState();
      sendResponse({
        ok: true,
        candidates: state.candidates,
        blockedDomains: state.blockedDomains,
        ignoredDomains: state.ignoredDomains,
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

Promise.all([
  rebuildUserDynamicRulesWithoutMainFrame(),
  installTurtlecuteHostRules(),
])
  .then(updateBadge)
  .catch((error) => {
    console.error("Startup rule installation failed:", error);
  });