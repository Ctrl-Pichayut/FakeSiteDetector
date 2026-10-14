import { computeScore } from "./scoring.js";

// ==========================================
// 1. PUNYCODE (RFC 3492) DECODER FOR REAL IDN HOMOGRAPHS
// ==========================================
function decodePunycode(input) {
  const maxInt = 2147483647;
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  const delimiter = "-";

  const output = [];
  const basic = input.lastIndexOf(delimiter);
  if (basic > 0) {
    for (let j = 0; j < basic; ++j) {
      output.push(input.charCodeAt(j));
    }
  }

  let i = 0;
  let n = initialN;
  let bias = initialBias;
  let pos = basic > 0 ? basic + 1 : 0;

  function adapt(delta, numPoints, firstTime) {
    let k = 0;
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  }

  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    let k = base;
    while (true) {
      if (pos >= input.length) break;
      let digit;
      const code = input.charCodeAt(pos++);
      if (code - 48 < 10) digit = code - 22;
      else if (code - 65 < 26) digit = code - 65;
      else if (code - 97 < 26) digit = code - 97;
      else digit = base;

      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
      k += base;
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

function toUnicodeDomain(domain) {
  return domain
    .split(".")
    .map((part) => {
      const lower = part.toLowerCase();
      if (lower.startsWith("xn--")) {
        try {
          return decodePunycode(lower.slice(4));
        } catch {
          return part;
        }
      }
      return part;
    })
    .join(".");
}

// Cyrillic & Greek lookalike confusables to Latin
const CONFUSABLE_LOOKALIKES = {
  "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p", "\u0441": "c",
  "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u04bb": "h",
  "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041A": "K", "\u041C": "M",
  "\u041D": "H", "\u041E": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
  "\u03BF": "o", "\u03C1": "p", "\u03C5": "u", "\u03BD": "v", "\u03B1": "a"
};

function analyzeHomograph(rawDomain) {
  const unicodeDomain = toUnicodeDomain(rawDomain);
  const isPunycode = rawDomain.toLowerCase().includes("xn--");

  const hasLatin = /[a-zA-Z]/.test(unicodeDomain);
  const hasCyrillic = /[\u0400-\u04FF]/.test(unicodeDomain);
  const hasGreek = /[\u0370-\u03FF]/.test(unicodeDomain);

  const confusableMatches = [];
  for (const ch of unicodeDomain) {
    if (CONFUSABLE_LOOKALIKES[ch]) {
      confusableMatches.push(`${ch} (U+${ch.charCodeAt(0).toString(16).toUpperCase()}) => ${CONFUSABLE_LOOKALIKES[ch]}`);
    }
  }

  const mixedScript = (hasLatin && hasCyrillic) || (hasLatin && hasGreek);
  let risk = 0;

  if (isPunycode && confusableMatches.length > 0) {
    risk = 0.95;
  } else if (mixedScript) {
    risk = 0.9;
  } else if (confusableMatches.length > 0) {
    risk = 0.75;
  }

  return {
    unicodeDomain,
    isPunycode,
    mixedScript,
    confusableMatches: [...new Set(confusableMatches)],
    risk
  };
}

// ==========================================
// 2. BRAND SPOOFING & TYPOSQUATTING ANALYZER
// ==========================================
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
    }
  }
  return d[m][n];
}

const BRAND_TARGETS = [
  { name: "paypal", official: ["paypal.com", "paypal.me"] },
  { name: "google", official: ["google.com", "google.co.th", "gmail.com"] },
  { name: "apple", official: ["apple.com", "icloud.com"] },
  { name: "microsoft", official: ["microsoft.com", "live.com", "office.com", "outlook.com"] },
  { name: "amazon", official: ["amazon.com"] },
  { name: "netflix", official: ["netflix.com"] },
  { name: "facebook", official: ["facebook.com", "fb.com", "meta.com"] },
  { name: "instagram", official: ["instagram.com"] },
  { name: "binance", official: ["binance.com", "binance.th"] },
  { name: "coinbase", official: ["coinbase.com"] },
  { name: "telegram", official: ["telegram.org", "t.me"] },
  { name: "discord", official: ["discord.com", "discord.gg"] },
  { name: "steam", official: ["steampowered.com", "steamcommunity.com"] },
  // Banking & Thai services
  { name: "kbank", official: ["kasikornbank.com", "kbank.co.th"] },
  { name: "scb", official: ["scb.co.th", "scbeasy.com"] },
  { name: "krungthai", official: ["krungthai.com"] },
  { name: "truemoney", official: ["truemoney.com"] },
  { name: "shopee", official: ["shopee.co.th", "shopee.com"] },
  { name: "lazada", official: ["lazada.co.th", "lazada.com"] }
];

function analyzeBrandSpoofing(domain) {
  const cleanDomain = domain.toLowerCase().replace(/^www\./, "");
  const parts = cleanDomain.split(".");
  // Label right before TLD
  const mainLabel = parts.length >= 2 ? parts[parts.length - 2] : parts[0];

  for (const brand of BRAND_TARGETS) {
    const isOfficial = brand.official.some(
      (off) => cleanDomain === off || cleanDomain.endsWith("." + off)
    );
    if (isOfficial) continue;

    // Check 1: Brand name embedded in non-official domain (e.g. paypal-security.com or apple.com.fake.xyz)
    if (cleanDomain.includes(brand.name)) {
      return {
        spoofedBrand: brand.name,
        type: "embedded_brand",
        risk: 0.85,
        detail: `Suspicious domain containing protected brand "${brand.name}"`
      };
    }

    // Check 2: Typosquatting (Levenshtein distance <= 1 or 2)
    const dist = levenshtein(mainLabel, brand.name);
    if (dist > 0 && dist <= (brand.name.length >= 6 ? 2 : 1)) {
      return {
        spoofedBrand: brand.name,
        type: "typosquatting",
        risk: 0.9,
        detail: `Likely typosquatting of brand "${brand.name}" (${mainLabel} differs by ${dist} char)`
      };
    }
  }

  return { spoofedBrand: null, risk: 0, detail: null };
}

// ==========================================
// 3. 100% FREE THREAT INTEL: CLOUDFLARE SECURITY DoH (1.1.1.2)
// ==========================================
async function checkDohThreat(domain) {
  try {
    const res = await fetch(
      `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      {
        headers: { Accept: "application/dns-json" },
        signal: AbortSignal.timeout(3500)
      }
    );

    if (!res.ok) {
      return { checked: false, reason: "DoH query returned non-200" };
    }

    const data = await res.json();
    if (data.Answer && Array.isArray(data.Answer)) {
      const isBlocked = data.Answer.some((ans) => ans.data === "0.0.0.0");
      if (isBlocked) {
        return {
          checked: true,
          blocked: true,
          status: "Blocked by Cloudflare Security Filter",
          ip: "0.0.0.0"
        };
      }
      return {
        checked: true,
        blocked: false,
        status: "Clean (Resolved)",
        ip: data.Answer[0]?.data || null
      };
    }

    if (data.Status === 3) {
      return {
        checked: true,
        blocked: false,
        status: "NXDOMAIN (Non-existent / Unregistered domain)"
      };
    }

    return { checked: true, blocked: false, status: "No A Record" };
  } catch (err) {
    return { checked: false, reason: err.message || "Timeout" };
  }
}

// ==========================================
// 4. SAFE CONTENT & FORM ANALYSIS (ZERO SCRIPT EXECUTION)
// ==========================================
const PHISHING_URGENCY_PATTERNS = [
  /verify (?:your )?account/i,
  /account (?:has been )?suspended/i,
  /unusual activity detected/i,
  /security alert/i,
  /enter (?:your )?(?:otp|pin|password)/i,
  /confirm your identity/i,
  /claim (?:your )?(?:prize|reward|free)/i,
  /giveaway/i,
  /limited time/i,
  /แจกเครดิตฟรี|เว็บตรง|สล็อต|บาคาร่า|ยืนยันรหัส otp|ระงับบัญชี/i
];

async function safeFetchAndAnalyze(targetUrl) {
  let isRedirected = false;
  let finalUrl = targetUrl;
  let crossDomain = false;
  let hasPasswordField = false;
  let externalFormAction = false;
  let htmlText = "";
  let networkFailed = false;
  let errorMessage = null;

  try {
    const initialUrlObj = new URL(targetUrl);
    const response = await fetch(targetUrl, {
      method: "GET",
      signal: AbortSignal.timeout(5000),
      redirect: "follow",
      cache: "no-store"
    });

    finalUrl = response.url;
    isRedirected = response.redirected;

    const finalUrlObj = new URL(finalUrl);
    if (
      isRedirected &&
      initialUrlObj.hostname.replace(/^www\./, "") !== finalUrlObj.hostname.replace(/^www\./, "")
    ) {
      crossDomain = true;
    }

    // Read first 200KB of HTML safely
    const reader = response.body?.getReader();
    if (reader) {
      let receivedBytes = 0;
      const chunks = [];
      while (receivedBytes < 200000) {
        const { done, value } = await reader.read();
        if (done || !value) break;
        chunks.push(value);
        receivedBytes += value.length;
      }
      const decoder = new TextDecoder();
      htmlText = chunks.map((c) => decoder.decode(c, { stream: true })).join("");
    } else {
      htmlText = await response.text();
    }

    // Inspect Forms & Password Inputs
    const passwordMatch = /<input[^>]*type=["']?password["']?/i.test(htmlText);
    if (passwordMatch) {
      hasPasswordField = true;
      // Check form action
      const formActionRegex = /<form[^>]*action=["']([^"']+)["']/gi;
      let match;
      while ((match = formActionRegex.exec(htmlText)) !== null) {
        const actionUrl = match[1];
        if (actionUrl.startsWith("http://") || actionUrl.startsWith("https://")) {
          try {
            const actionHost = new URL(actionUrl).hostname.replace(/^www\./, "");
            if (actionHost !== finalUrlObj.hostname.replace(/^www\./, "")) {
              externalFormAction = true;
            }
          } catch {}
        }
      }
    }
  } catch (err) {
    networkFailed = true;
    errorMessage = err.message || "Connection timed out or failed";
  }

  // Phishing text matches
  const keywordHits = [];
  if (htmlText) {
    for (const pattern of PHISHING_URGENCY_PATTERNS) {
      const match = htmlText.match(pattern);
      if (match) {
        keywordHits.push(match[0].toLowerCase());
      }
    }
  }

  let formRisk = 0;
  if (hasPasswordField && externalFormAction) {
    formRisk = 0.9;
  } else if (hasPasswordField && !targetUrl.startsWith("https://")) {
    formRisk = 0.8;
  } else if (hasPasswordField) {
    formRisk = 0.2;
  }

  const textRisk = Math.min(1, keywordHits.length * 0.25);
  const redirectRisk = crossDomain ? 0.8 : isRedirected ? 0.3 : 0;

  return {
    finalUrl,
    isRedirected,
    crossDomain,
    hasPasswordField,
    externalFormAction,
    formRisk,
    textRisk,
    redirectRisk,
    keywordHits: [...new Set(keywordHits)],
    networkFailed,
    errorMessage
  };
}

// ==========================================
// 5. TAB SCAN CACHE, BADGE & NAVIGATION AUTO-SCAN
// ==========================================
const tabScanCache = new Map(); // tabId -> { url, result, timestamp }
const inFlightScans = new Map(); // normalizedUrl -> Promise<result>
let autoScanEnabled = true;

// Initialize settings from storage
chrome.storage.local.get(["autoScanEnabled"]).then((res) => {
  if (typeof res.autoScanEnabled === "boolean") {
    autoScanEnabled = res.autoScanEnabled;
  }
});

function updateBadge(tabId, level) {
  if (!tabId || tabId < 0) return;
  try {
    if (level === "safe") {
      chrome.action.setBadgeText({ tabId, text: "OK" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#238636" });
    } else if (level === "moderate") {
      chrome.action.setBadgeText({ tabId, text: "WARN" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#d29922" });
    } else if (level === "danger") {
      chrome.action.setBadgeText({ tabId, text: "RISK" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#da3633" });
    } else if (level === "scanning") {
      chrome.action.setBadgeText({ tabId, text: "..." });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#58a6ff" });
    } else {
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  } catch {
    // Tab may be closed or not found
  }
}

// Background auto-scan on tab navigation
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (!autoScanEnabled) return;
  if (changeInfo.status !== "complete" && !changeInfo.url) return;

  const url = changeInfo.url || tab?.url;
  if (!url) return;

  // Ignore non-HTTP/HTTPS URLs (browser internal pages)
  if (!/^https?:\/\//i.test(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    tabScanCache.delete(tabId);
    return;
  }

  // Avoid re-scanning same URL on the same tab within 60s
  const cached = tabScanCache.get(tabId);
  if (cached && cached.url === url && Date.now() - cached.timestamp < 60000) {
    updateBadge(tabId, cached.result.scores.safetyLevel);
    return;
  }

  updateBadge(tabId, "scanning");

  try {
    const result = await analyzeUrl(url);
    tabScanCache.set(tabId, { url, result, timestamp: Date.now() });
    updateBadge(tabId, result.scores.safetyLevel);
  } catch (err) {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
});

// Clean up memory cache on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  tabScanCache.delete(tabId);
});

// Sync badge when switching between tabs
chrome.tabs.onActivated.addListener((activeInfo) => {
  const cached = tabScanCache.get(activeInfo.tabId);
  if (cached) {
    updateBadge(activeInfo.tabId, cached.result.scores.safetyLevel);
  } else {
    chrome.action.setBadgeText({ tabId: activeInfo.tabId, text: "" });
  }
});

// Runtime message orchestrator
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "ANALYZE_URL") {
    analyzeUrl(message.url)
      .then((result) => {
        if (message.tabId) {
          tabScanCache.set(message.tabId, { url: message.url, result, timestamp: Date.now() });
          updateBadge(message.tabId, result.scores.safetyLevel);
        }
        sendResponse({ ok: true, result });
      })
      .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  if (message?.type === "GET_TAB_SCAN") {
    const tabId = message.tabId;
    const url = message.url;
    const cached = tabScanCache.get(tabId);

    if (cached && (!url || cached.url === url)) {
      sendResponse({ ok: true, cached: true, result: cached.result });
    } else {
      sendResponse({ ok: true, cached: false });
    }
    return true;
  }

  if (message?.type === "GET_AUTO_SCAN") {
    sendResponse({ ok: true, autoScanEnabled });
    return true;
  }

  if (message?.type === "SET_AUTO_SCAN") {
    autoScanEnabled = Boolean(message.enabled);
    chrome.storage.local.set({ autoScanEnabled });
    if (!autoScanEnabled) {
      chrome.tabs.query({}).then((tabs) => {
        tabs.forEach((t) => {
          if (t.id) chrome.action.setBadgeText({ tabId: t.id, text: "" });
        });
      });
    }
    sendResponse({ ok: true, autoScanEnabled });
    return true;
  }

  return false;
});

async function analyzeUrl(rawUrl) {
  const normalizedUrl = normalizeInputUrl(rawUrl);

  if (inFlightScans.has(normalizedUrl)) {
    return inFlightScans.get(normalizedUrl);
  }

  const scanPromise = (async () => {
    const startedAt = new Date();
    const t0 = performance.now();

    const urlObj = new URL(normalizedUrl);
    const domain = urlObj.hostname;
    const isHttp = urlObj.protocol === "http:";

    // Run independent checks concurrently for maximum speed
    const [dohResult, homographResult, brandResult, contentResult] = await Promise.all([
      checkDohThreat(domain),
      analyzeHomograph(domain),
      analyzeBrandSpoofing(domain),
      safeFetchAndAnalyze(normalizedUrl)
    ]);

    const scoreResult = computeScore({
      dohBlocked: dohResult.blocked || false,
      homographRisk: homographResult.risk,
      brandRisk: brandResult.risk,
      formRisk: contentResult.formRisk,
      textRisk: contentResult.textRisk,
      redirectRisk: contentResult.redirectRisk,
      isHttp,
      networkFailed: contentResult.networkFailed
    });

    const t1 = performance.now();
    const durationMs = Math.round(t1 - t0);

    const result = {
      scan_id: crypto.randomUUID(),
      url: normalizedUrl,
      final_url: contentResult.finalUrl,
      domain,
      protocol: isHttp ? "HTTP (Insecure)" : "HTTPS (Secure)",
      started_at: startedAt.toISOString(),
      duration_ms: durationMs,
      duration_sec: Number((durationMs / 1000).toFixed(2)),
      scores: scoreResult,
      signals: {
        doh: {
          checked: dohResult.checked,
          blocked: dohResult.blocked || false,
          status: dohResult.status || dohResult.reason
        },
        homograph: {
          unicodeDomain: homographResult.unicodeDomain,
          isPunycode: homographResult.isPunycode,
          mixedScript: homographResult.mixedScript,
          confusableMatches: homographResult.confusableMatches,
          risk: homographResult.risk
        },
        brand: {
          spoofedBrand: brandResult.spoofedBrand,
          detail: brandResult.detail,
          risk: brandResult.risk
        },
        content: {
          isRedirected: contentResult.isRedirected,
          crossDomain: contentResult.crossDomain,
          hasPasswordField: contentResult.hasPasswordField,
          externalFormAction: contentResult.externalFormAction,
          keywordHits: contentResult.keywordHits,
          networkFailed: contentResult.networkFailed,
          errorMessage: contentResult.errorMessage
        }
      }
    };

    await saveScanHistory(result);
    return result;
  })();

  inFlightScans.set(normalizedUrl, scanPromise);
  try {
    return await scanPromise;
  } finally {
    inFlightScans.delete(normalizedUrl);
  }
}

function normalizeInputUrl(rawUrl) {
  let value = String(rawUrl || "").trim();
  if (!value) {
    throw new Error("URL is required.");
  }
  if (!/^https?:\/\//i.test(value)) {
    value = `https://${value}`;
  }
  return value;
}

async function saveScanHistory(result) {
  try {
    const storage = await chrome.storage.local.get(["scanHistory"]);
    const current = Array.isArray(storage.scanHistory) ? storage.scanHistory : [];
    const next = [result, ...current].slice(0, 20);
    await chrome.storage.local.set({ scanHistory: next });
  } catch {
    // Ignore storage errors
  }
}
