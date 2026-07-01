let activeAlert = null;

function closeTheBlockerAlert() {
  if (activeAlert) {
    activeAlert.remove();
    activeAlert = null;
  }
}

function createButton(label, variant) {
  const button = document.createElement("button");

  button.textContent = label;
  button.style.border = "0";
  button.style.borderRadius = "12px";
  button.style.padding = "10px 14px";
  button.style.fontWeight = "800";
  button.style.cursor = "pointer";

  if (variant === "danger") {
    button.style.color = "#101318";
    button.style.background = "#9effa6";
  } else {
    button.style.color = "#f5f7fb";
    button.style.background = "rgba(255,255,255,0.1)";
  }

  return button;
}

function showTheBlockerAlert(candidate) {
  if (activeAlert) {
    return;
  }

  const backdrop = document.createElement("div");
  activeAlert = backdrop;

  backdrop.style.position = "fixed";
  backdrop.style.inset = "0";
  backdrop.style.zIndex = "2147483647";
  backdrop.style.display = "grid";
  backdrop.style.placeItems = "center";
  backdrop.style.background = "rgba(3, 6, 12, 0.58)";
  backdrop.style.backdropFilter = "blur(8px)";
  backdrop.style.fontFamily =
    "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";

  const card = document.createElement("div");
  card.style.width = "min(460px, calc(100vw - 32px))";
  card.style.boxSizing = "border-box";
  card.style.border = "1px solid rgba(255, 210, 120, 0.28)";
  card.style.borderRadius = "22px";
  card.style.padding = "20px";
  card.style.color = "#f5f7fb";
  card.style.background = "#151922";
  card.style.boxShadow = "0 28px 90px rgba(0, 0, 0, 0.48)";

  const title = document.createElement("h2");
  title.textContent = "Possible Ad Domain Detected";
  title.style.margin = "0 0 10px";
  title.style.fontSize = "20px";

  const copy = document.createElement("p");
  copy.textContent =
    "The Blocker noticed a browser request that looks related to ads or tracking.";
  copy.style.margin = "0 0 16px";
  copy.style.color = "#9aa6ba";
  copy.style.lineHeight = "1.45";

  const domainBox = document.createElement("div");
  domainBox.style.display = "grid";
  domainBox.style.gap = "6px";
  domainBox.style.margin = "16px 0";
  domainBox.style.padding = "14px";
  domainBox.style.border = "1px solid rgba(255, 210, 120, 0.2)";
  domainBox.style.borderRadius = "14px";
  domainBox.style.background = "rgba(255, 210, 120, 0.08)";

  const domainLabel = document.createElement("span");
  domainLabel.textContent = "Domain";
  domainLabel.style.color = "#9aa6ba";
  domainLabel.style.fontSize = "12px";
  domainLabel.style.fontWeight = "800";
  domainLabel.style.textTransform = "uppercase";
  domainLabel.style.letterSpacing = "0.08em";

  const domainText = document.createElement("strong");
  domainText.textContent = candidate.domain;
  domainText.style.overflowWrap = "anywhere";

  domainBox.append(domainLabel, domainText);

  const reason = document.createElement("p");
  reason.textContent = candidate.reason;
  reason.style.margin = "0 0 18px";
  reason.style.color = "#9aa6ba";
  reason.style.lineHeight = "1.45";

  const actions = document.createElement("div");
  actions.style.display = "flex";
  actions.style.justifyContent = "flex-end";
  actions.style.gap = "10px";

  const ignoreButton = createButton("Don't Block", "secondary");
  const blockButton = createButton("Block Domain", "danger");

  ignoreButton.addEventListener("click", () => {
    chrome.runtime.sendMessage(
      {
        type: "IGNORE_DOMAIN",
        domain: candidate.domain,
      },
      closeTheBlockerAlert
    );
  });

  blockButton.addEventListener("click", () => {
    chrome.runtime.sendMessage(
      {
        type: "BLOCK_DOMAIN",
        domain: candidate.domain,
      },
      closeTheBlockerAlert
    );
  });

  actions.append(ignoreButton, blockButton);
  card.append(title, copy, domainBox, reason, actions);
  backdrop.append(card);
  document.documentElement.append(backdrop);
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SHOW_AD_CANDIDATE") {
    showTheBlockerAlert(message.candidate);
  }
});