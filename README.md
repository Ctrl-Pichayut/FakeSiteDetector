<p align="center">
  <h1 align="center">🛡️ FakeSiteDetector (FSD)</h1>
  <p align="center">
    <strong>Real-Time Browser Extension for Anti-Phishing, IDN Homographs & Website Safety Verification</strong>
    <br />
    100% Free, Unlimited & Keyless — Zero API Keys, Zero Cloud Infrastructure Costs, and No Dangerous Tab Script Execution.
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Manifest-V3-4285F4?logo=googlechrome&logoColor=white" alt="Manifest V3" />
    <img src="https://img.shields.io/badge/JavaScript-ES%20Modules-F7DF1E?logo=javascript&logoColor=black" alt="JavaScript" />
    <img src="https://img.shields.io/badge/Threat%20Intel-Cloudflare%201.1.1.2%20DoH-F38020?logo=cloudflare&logoColor=white" alt="Cloudflare DoH" />
    <img src="https://img.shields.io/badge/Architecture-Keyless%20%26%20Zero--Cost-238636" alt="Keyless" />
    <img src="https://img.shields.io/badge/Platform-Chrome%20%7C%20Edge%20%7C%20Brave-3178C6" alt="Browsers" />
    <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License" />
  </p>
</p>

---

## 🌟 Executive Overview

**FakeSiteDetector (FSD)** is a lightweight browser extension designed to protect users against phishing campaigns, deceptive lookalike domains, brand typosquatting, and credential harvesting in real-time.

### Why Traditional Security Extensions Fall Short:
Most website security extensions rely on third-party commercial APIs (such as VirusTotal, Google Safe Browsing, or IPQualityScore):
1. **API Key Leakage:** Putting private API keys into client-side browser extensions exposes them to extraction via Chrome DevTools.
2. **Quota Depletion:** Free API tiers cap out after a few dozen scans a day, breaking the extension for real-world browsing.
3. **Privacy Concerns:** Every visited URL is sent to third-party proprietary trackers.

### The FSD Keyless Architecture:
**FakeSiteDetector operates 100% locally and keylessly.** It leverages:
- **Cloudflare Security DNS-over-HTTPS (1.1.1.2)** for free, real-time threat blocklist queries without an API token.
- **Client-Side RFC 3492 Punycode Engine** for detecting Cyrillic/Greek character substitution.
- **Levenshtein Distance & Subdomain Parsing** for brand typosquatting defense.
- **Safe HTML Stream Inspection** using `AbortSignal.timeout(5000)` without executing untrusted JavaScript in the browser.

---

## 🚀 Key Features

- ⚡ **Zero-Click Active Tab Scanning:** Open the extension popup, and it immediately analyzes the active tab. No need to click extra buttons.
- 🟢 **Proactive Toolbar Icon Badges:** As you browse, the extension monitors navigation in the background and tags the toolbar badge:
  - 🟢 **`OK`**: Verified safe site.
  - 🟡 **`WARN`**: Unencrypted HTTP or minor warning signals.
  - 🔴 **`RISK`**: Phishing, homograph lookalike, or malicious domain detected.
- 🔤 **IDN Homograph & Punycode Defense:** Full RFC 3492 decoder that identifies deceptive Unicode domain substitutions (e.g., `xn--80akxla.com` $\rightarrow$ `аррне.com`).
- 🏢 **Brand Typosquatting & Subdomain Traps:** Guards high-value targets (Google, Apple, Microsoft, PayPal, Binance) and regional platforms (SCB, KBank, TrueMoney, Shopee) against deceptive names like `paypa1.com` or `apple.com.login-verify.xyz`.
- 🔒 **Credential Harvesting Form Audit:** Scans page markup to detect `<input type="password">` fields posting credentials to external unverified domains.
- ⏱️ **Sub-50ms Instant Memory Cache:** Remembers recently scanned tabs to render cached results instantaneously with zero latency.
- 📋 **Local Scan History:** Keeps a private, encrypted log of recent audits stored strictly inside `chrome.storage.local`.

---

## 📐 System Architecture

```
                       [User Visits Website]
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        CHROME SERVICE WORKER                           │
│   chrome.tabs.onUpdated • In-Flight Deduplication • Session Cache      │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
    ┌────────────────────────────┼────────────────────────────┐
    │                            │                            │
    ▼                            ▼                            ▼
┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
│ Cloudflare 1.1.1.2 DoH  │ │ RFC 3492 Punycode Engine│ │ Levenshtein Brand Check │
│ DNS-over-HTTPS Threat   │ │ Cyrillic / Greek Unicode│ │ Typosquatting &         │
│ Intelligence (Keyless)  │ │ Lookalike Decoder       │ │ Deceptive Subdomains    │
└───────────┬─────────────┘ └───────────┬─────────────┘ └───────────┬─────────────┘
            │                           │                           │
            └───────────────────────────┼───────────────────────────┘
                                        │
                                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        COMPOSITE SCORING ENGINE                        │
│   Calculates Safety Score (-100 to 100) & Categorizes Risk Tier        │
└───────────────────────────────────────┬────────────────────────────────┘
                                        │
                         Updates Badge & Caches Result
                                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       MODERNIZED POPUP INTERFACE                       │
│   • Instant Zero-Click Result Rendering                                │
│   • Live Status Dot (Safe / Moderate / Danger)                         │
│   • 1-Click Re-scan Button & Manual Link Inspection Bar                │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Scoring Formula & Tiers

The composite score ranges from **-100 to 100 points**:

| Score Range | Tier | Badge | Description |
| :---: | :---: | :---: | :--- |
| **51 to 100** | **SAFE** | 🟢 `OK` | Clean domain structure, passed security DNS, HTTPS encrypted, authentic brand. |
| **1 to 50** | **MODERATE** | 🟡 `WARN` | Insecure HTTP, unverified connection, or non-critical risk keywords. |
| **-100 to 0** | **DANGER** | 🔴 `RISK` | Active homograph attack, brand impersonation, credential harvesting, or Cloudflare threat block. |

---

## 📥 How to Install & Run

FakeSiteDetector is packaged as a **Manifest V3** unpacked extension compatible with **Google Chrome**, **Brave**, **Microsoft Edge**, and **Opera**.

### Step 1: Clone or Download this Repository
```bash
git clone https://github.com/Ctrl-Pichayut/FakeSiteDetector.git
```
*(Or download and extract the ZIP archive).*

### Step 2: Load into Your Browser
1. Open your browser and navigate to the Extensions management page:
   - **Chrome:** `chrome://extensions`
   - **Brave:** `brave://extensions`
   - **Edge:** `edge://extensions`
2. Enable **Developer mode** (toggle located in the top-right corner).
3. Click the **Load unpacked** button in the top-left corner.
4. Select the project directory (`FakeSiteDetector` or `RealFSD`).
5. **Pin the extension** to your browser toolbar for quick access.

---

## 🧪 How to Test & Verify

Try testing these scenarios to observe real-time detection in action:

| Scenario | Test URL | Expected Outcome |
| :--- | :--- | :--- |
| **Legitimate Site** | `https://google.com` | **Score: 100 (Safe 🟢)** — Clean domain, passed DoH threat intel. |
| **Brand Typosquatting** | `http://paypa1.com` | **Score: < 0 (Danger 🔴)** — Flags brand impersonation against `paypal`. |
| **Cyrillic Homograph Attack** | `https://xn--80akxla.com` | **Score: < 0 (Danger 🔴)** — Decodes to `аррне.com` with Russian character substitutions. |
| **Subdomain Phishing Trap** | `https://apple.com.security-verify.xyz` | **Score: < 0 (Danger 🔴)** — Flags deceptive embedded brand in subdomains. |
| **Insecure HTTP Protocol** | `http://neverssl.com` | **Score: 80 (Moderate 🟡)** — Flags unencrypted plaintext communication. |

---

## 📂 Project Directory Structure

```
FakeSiteDetector/
├── manifest.json       # Manifest V3 specification & permission declarations
├── background.js       # Service worker: navigation listener, DoH resolver, badge controller
├── scoring.js          # Heuristic scoring engine & penalty synergy matrix
├── popup.html          # Extension popup markup
├── popup.css           # High-contrast cyber-security styling & animations
├── popup.js            # Zero-click auto-scan controller & history manager
├── assets/
│   └── logo.png        # Official project branding logo
└── README.md           # Documentation & verification walkthrough
```

---

## 📄 License & Attribution

Developed by **Pichayut Jeawpongpipat** ([@Ctrl-Pichayut](https://github.com/Ctrl-Pichayut)) as an engineering project. Released under the [MIT License](LICENSE).
