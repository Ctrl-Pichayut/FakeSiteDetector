import { scoreToBarPercent } from "./scoring.js";

// DOM Elements
const currentDomain = document.getElementById("currentDomain");
const siteStatusDot = document.getElementById("siteStatusDot");
const rescanBtn = document.getElementById("rescanBtn");
const internalNotice = document.getElementById("internalNotice");
const analyzeBtn = document.getElementById("analyzeBtn");
const urlInput = document.getElementById("urlInput");
const loader = document.getElementById("loader");
const resultCard = document.getElementById("resultCard");
const scoreValue = document.getElementById("scoreValue");
const tierBadge = document.getElementById("tierBadge");
const scoreBar = document.getElementById("scoreBar");
const summaryText = document.getElementById("summaryText");
const domainMeta = document.getElementById("domainMeta");
const timeMeta = document.getElementById("timeMeta");
const signalsList = document.getElementById("signalsList");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

let currentActiveTab = null;

// Event Listeners
document.addEventListener("DOMContentLoaded", async () => {
  loadHistory();

  if (rescanBtn) {
    rescanBtn.addEventListener("click", () => {
      if (currentActiveTab?.url) {
        runScan(currentActiveTab.url, currentActiveTab.id, true);
      }
    });
  }

  analyzeBtn.addEventListener("click", () => runScan(urlInput.value.trim()));
  clearHistoryBtn.addEventListener("click", clearHistory);

  urlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      runScan(urlInput.value.trim());
    }
  });

  // Zero-click automatic scan on active tab immediately
  await autoScanActiveTab();
});

async function autoScanActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      if (currentDomain) currentDomain.textContent = "No active tab";
      return;
    }

    currentActiveTab = tab;
    const url = tab.url;

    // Check if internal browser page
    if (!/^https?:\/\//i.test(url)) {
      if (currentDomain) currentDomain.textContent = "System Page";
      if (siteStatusDot) siteStatusDot.className = "site-status-dot";
      if (internalNotice) internalNotice.classList.remove("hidden");
      if (resultCard) resultCard.classList.add("hidden");
      return;
    }

    if (internalNotice) internalNotice.classList.add("hidden");

    // Display active domain in header
    try {
      const urlObj = new URL(url);
      if (currentDomain) currentDomain.textContent = urlObj.hostname;
    } catch {
      if (currentDomain) currentDomain.textContent = url;
    }

    // Check background cache first (< 10ms instantaneous rendering)
    const cacheRes = await chrome.runtime.sendMessage({
      type: "GET_TAB_SCAN",
      tabId: tab.id,
      url
    });

    if (cacheRes?.ok && cacheRes?.cached && cacheRes?.result) {
      renderResult(cacheRes.result);
      return;
    }

    // Not cached yet -> run scan immediately without needing any click
    await runScan(url, tab.id);
  } catch (err) {
    console.error("Auto scan init error:", err);
  }
}

async function runScan(url, tabId, isForceRescan = false) {
  if (!url) {
    alert("Please enter a valid URL.");
    return;
  }

  setLoading(true);
  resultCard.classList.add("hidden");
  if (internalNotice) internalNotice.classList.add("hidden");

  try {
    const response = await chrome.runtime.sendMessage({
      type: "ANALYZE_URL",
      url,
      tabId: tabId || currentActiveTab?.id
    });

    if (!response || !response.ok) {
      throw new Error(response?.error || "Scanning failed.");
    }

    renderResult(response.result);
    await loadHistory();
  } catch (err) {
    alert("Scan failed: " + (err.message || String(err)));
  } finally {
    setLoading(false);
  }
}

function renderResult(result) {
  resultCard.classList.remove("hidden");

  const scores = result.scores;
  const score = scores.safetyScore;
  const level = scores.safetyLevel;

  // Update Active Site Dot & Domain
  if (siteStatusDot) {
    siteStatusDot.className = `site-status-dot ${level}`;
  }
  if (currentDomain) {
    currentDomain.textContent = result.domain;
  }

  // Animated Score
  animateScore(scoreValue, parseInt(scoreValue.textContent) || 0, score, 600);

  // Badge & Summary
  tierBadge.textContent = level.toUpperCase();
  tierBadge.className = `tier-badge ${level}`;
  summaryText.textContent = scores.summary;

  // Bar Progress & Color
  const percent = scoreToBarPercent(score);
  scoreBar.style.width = `${percent}%`;
  scoreBar.style.background = getLevelColor(level);

  // Meta items
  domainMeta.textContent = `🌐 ${result.domain}`;
  timeMeta.textContent = `⏱️ ${result.duration_sec}s (${result.protocol})`;

  // Breakdown Signals
  const signals = result.signals;
  const items = [];

  // 1. Cloudflare DoH Threat Intelligence
  if (signals.doh.blocked) {
    items.push({
      type: "danger",
      text: `🚨 <b>Threat Intel:</b> BLOCKED by Cloudflare 1.1.1.2 Security Filter (Known Malware/Phishing)`
    });
  } else if (signals.doh.checked) {
    items.push({
      type: "clean",
      text: `🛡️ <b>Threat Intel:</b> Cloudflare Security DNS passed (${escapeHtml(signals.doh.status)})`
    });
  }

  // 2. Homograph / Punycode Analysis
  if (signals.homograph.isPunycode || signals.homograph.mixedScript) {
    const matchStr = signals.homograph.confusableMatches.join(", ") || "Mixed script detected";
    items.push({
      type: "danger",
      text: `🔤 <b>Homograph Attack:</b> Deceptive unicode domain detected: <code>${escapeHtml(signals.homograph.unicodeDomain)}</code> (${escapeHtml(matchStr)})`
    });
  } else if (signals.homograph.confusableMatches.length > 0) {
    items.push({
      type: "warning",
      text: `🔤 <b>Lookalike Chars:</b> ${escapeHtml(signals.homograph.confusableMatches.join(", "))}`
    });
  } else {
    items.push({
      type: "clean",
      text: `🔤 <b>Homograph Check:</b> Normal standard Latin domain charset`
    });
  }

  // 3. Brand Spoofing / Typosquatting
  if (signals.brand.spoofedBrand) {
    items.push({
      type: "danger",
      text: `🏢 <b>Brand Impersonation:</b> ${escapeHtml(signals.brand.detail)}`
    });
  } else {
    items.push({
      type: "clean",
      text: `🏢 <b>Brand Check:</b> No brand spoofing or typosquatting detected`
    });
  }

  // 4. Forms & Credential Security
  if (signals.content.hasPasswordField) {
    if (signals.content.externalFormAction) {
      items.push({
        type: "danger",
        text: `🔒 <b>Credential Risk:</b> Login form sends passwords to an EXTERNAL domain!`
      });
    } else if (result.protocol.includes("HTTP (Insecure)")) {
      items.push({
        type: "danger",
        text: `🔒 <b>Credential Risk:</b> Password form found on unencrypted HTTP connection!`
      });
    } else {
      items.push({
        type: "warning",
        text: `🔒 <b>Login Form:</b> Password input detected on page`
      });
    }
  }

  // 5. Phishing Urgency Keywords
  if (signals.content.keywordHits && signals.content.keywordHits.length > 0) {
    items.push({
      type: "warning",
      text: `⚠️ <b>Suspicious Phrases:</b> Found: "${escapeHtml(signals.content.keywordHits.join('", "'))}"`
    });
  }

  // 6. Redirects
  if (signals.content.crossDomain) {
    items.push({
      type: "danger",
      text: `🔀 <b>Redirect:</b> Jumped across different domains to <code>${escapeHtml(result.final_url)}</code>`
    });
  } else if (signals.content.isRedirected) {
    items.push({
      type: "clean",
      text: `🔀 <b>Redirect:</b> Safe internal redirect to <code>${escapeHtml(result.final_url)}</code>`
    });
  }

  // Render Signals
  signalsList.innerHTML = items
    .map((item) => `<li class="signal-${item.type}">${item.text}</li>`)
    .join("");
}

function setLoading(isLoading) {
  if (isLoading) {
    loader.classList.remove("hidden");
    analyzeBtn.disabled = true;
    if (rescanBtn) rescanBtn.classList.add("spinning");
  } else {
    loader.classList.add("hidden");
    analyzeBtn.disabled = false;
    if (rescanBtn) rescanBtn.classList.remove("spinning");
  }
}

async function loadHistory() {
  try {
    const { scanHistory = [] } = await chrome.storage.local.get(["scanHistory"]);
    historyList.innerHTML = "";

    if (!scanHistory.length) {
      historyList.innerHTML = `<li class="empty-history">No recent scans yet</li>`;
      return;
    }

    for (const scan of scanHistory.slice(0, 5)) {
      const li = document.createElement("li");
      const level = scan.scores.safetyLevel || "safe";
      li.innerHTML = `
        <span class="history-domain" title="${escapeHtml(scan.url)}">${escapeHtml(scan.domain)}</span>
        <span class="history-badge ${level}">${scan.scores.safetyScore} pts (${level})</span>
      `;
      li.style.cursor = "pointer";
      li.addEventListener("click", () => {
        urlInput.value = scan.url;
        renderResult(scan);
      });
      historyList.appendChild(li);
    }
  } catch {
    // Ignore history load errors
  }
}

async function clearHistory() {
  await chrome.storage.local.remove(["scanHistory"]);
  await loadHistory();
}

function getLevelColor(level) {
  if (level === "danger") return "#f85149";
  if (level === "moderate") return "#d29922";
  return "#2ea043";
}

function animateScore(el, start, end, duration) {
  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    const easeProgress = 1 - (1 - progress) * (1 - progress);
    const currentVal = Math.floor(easeProgress * (end - start) + start);
    el.textContent = currentVal;
    if (progress < 1) {
      window.requestAnimationFrame(step);
    } else {
      el.textContent = end;
    }
  };
  window.requestAnimationFrame(step);
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
