/**
 * scoring.js - Safety scoring algorithm for Website Safety Scanner
 * Pure function: calculates normalized score (-100 to 100) and risk tier
 */

export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

export function normalizeSafetyScore(score) {
  return clamp(score, -100, 100);
}

export function getSafetyLevel(score) {
  if (score <= 0) {
    return "danger";
  }
  if (score <= 50) {
    return "moderate";
  }
  return "safe";
}

export function scoreToBarPercent(score) {
  const normalized = normalizeSafetyScore(score);
  return ((normalized + 100) / 200) * 100;
}

/**
 * Computes composite safety score from on-device heuristics & DoH threat signals
 *
 * @param {Object} signals
 * @param {boolean} signals.dohBlocked - Blocked by Cloudflare Security Threat Intel (0.0.0.0)
 * @param {number} signals.homographRisk - 0 to 1 (Punycode / confusable Cyrillic)
 * @param {number} signals.brandRisk - 0 to 1 (Typosquatting / spoofed high-value brand)
 * @param {number} signals.formRisk - 0 to 1 (Insecure password form / external submission)
 * @param {number} signals.textRisk - 0 to 1 (Urgency / credential harvesting keywords)
 * @param {number} signals.redirectRisk - 0 to 1 (Cross-domain redirects)
 * @param {boolean} signals.isHttp - Unencrypted HTTP
 * @param {boolean} signals.networkFailed - Connection timed out or refused
 */
export function computeScore({
  dohBlocked = false,
  homographRisk = 0,
  brandRisk = 0,
  formRisk = 0,
  textRisk = 0,
  redirectRisk = 0,
  isHttp = false,
  networkFailed = false
}) {
  // If explicitly flagged by threat intelligence: instantaneous critical penalty
  if (dohBlocked) {
    return {
      safetyScore: -100,
      safetyLevel: "danger",
      riskTotal: 1.0,
      breakdown: {
        dohPenalty: 200,
        homographPenalty: 0,
        brandPenalty: 0,
        formPenalty: 0,
        textPenalty: 0,
        redirectPenalty: 0,
        httpPenalty: 0
      },
      summary: "Blocked by Cloudflare Security Threat Intelligence (Known Malicious/Phishing Domain)"
    };
  }

  let penalty = 0;

  // 1. Homograph / Confusable attacks (extremely dangerous deceptive technique)
  let homographPenalty = 0;
  if (homographRisk >= 0.8) {
    homographPenalty = 110;
  } else if (homographRisk > 0) {
    homographPenalty = Math.round(homographRisk * 80);
  }
  penalty += homographPenalty;

  // 2. Brand Spoofing & Typosquatting (e.g. paypa1.com, g00gle.com)
  let brandPenalty = 0;
  if (brandRisk >= 0.8) {
    brandPenalty = 110;
  } else if (brandRisk > 0) {
    brandPenalty = Math.round(brandRisk * 75);
  }
  penalty += brandPenalty;

  // 3. Form & Credential Harvesting Risks (e.g. password field submitting to external domain)
  let formPenalty = Math.round(clamp(formRisk, 0, 1) * 55);
  penalty += formPenalty;

  // 4. Cross-domain redirects
  let redirectPenalty = Math.round(clamp(redirectRisk, 0, 1) * 35);
  penalty += redirectPenalty;

  // 5. Phishing / Urgency keyword matches in page text
  let textPenalty = Math.round(clamp(textRisk, 0, 1) * 30);
  penalty += textPenalty;

  // 6. Insecure HTTP protocol
  let httpPenalty = isHttp ? 20 : 0;
  penalty += httpPenalty;

  // 7. Network connection failure / unreachability
  let networkPenalty = networkFailed ? 15 : 0;
  penalty += networkPenalty;

  // Synergy amplification: if multiple severe threat signals trigger simultaneously
  const severeSignalsCount = [
    homographRisk >= 0.5,
    brandRisk >= 0.5,
    formRisk >= 0.5,
    redirectRisk >= 0.5
  ].filter(Boolean).length;

  if (severeSignalsCount >= 2) {
    penalty += 30;
  }

  const rawScore = 100 - penalty;
  const safetyScore = normalizeSafetyScore(rawScore);
  const safetyLevel = getSafetyLevel(safetyScore);
  const riskTotal = clamp(penalty / 200, 0, 1);

  return {
    safetyScore,
    safetyLevel,
    riskTotal: Number(riskTotal.toFixed(3)),
    breakdown: {
      homographPenalty,
      brandPenalty,
      formPenalty,
      redirectPenalty,
      textPenalty,
      httpPenalty,
      networkPenalty
    },
    summary:
      safetyLevel === "danger"
        ? "High risk detected. Avoid entering credentials or personal information."
        : safetyLevel === "moderate"
          ? "Moderate risk signals detected. Proceed with caution."
          : "No significant threat indicators found. Basic verification passed."
  };
}
