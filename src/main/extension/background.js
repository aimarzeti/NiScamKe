/**
 * Ni Scam Ke? - Background Service Worker
 * Uses the live backend first, then falls back to local rules so the demo never feels broken.
 */

const API_BASE_URL = "http://localhost:8080";
const LIVE_BACKEND_ENABLED = true;
const LIVE_SCAMSHIELD_SCAN_ROUTE = `${API_BASE_URL}/api/v1/scan-url`;

const TRUSTED_DOMAINS = [
    "maybank2u.com.my",
    "maybank.com",
    "cimbclicks.com.my",
    "cimb.com.my",
    "bankislam.com.my",
    "beubankislam.com.my",
    "rhbbank.com.my",
    "pbebank.com",
    "publicbank.com.my",
    "hongleongbank.com.my",
    "mybsn.com.my"
];

const BANK_KEYWORDS = [
    "bimb",
    "bankislam",
    "cimb",
    "maybank",
    "rhb",
    "hongleong",
    "publicbank",
    "ambank",
    "affin",
    "bsn",
    "agro"
];

const BANK_LOOKALIKE_TERMS = [
    "maybank",
    "maybank2u",
    "cimb",
    "cimbclicks",
    "bankislam",
    "bimb",
    "rhb",
    "rhbbank",
    "hongleong",
    "hongleongbank",
    "publicbank",
    "pbebank",
    "ambank",
    "affin",
    "bsn",
    "mybsn",
    "agrobank"
];

const SUSPICIOUS_PATTERNS = [
    "secure-login",
    "verify-account",
    "account-suspended",
    "login-update",
    "bank-verification",
    "maybank-secure",
    "cimb-secure",
    "bankislam-secure",
    "otp",
    "claim"
];

const APPLICATION_SCAM_BAIT_TERMS = [
    "bantuan",
    "percuma",
    "free",
    "claim",
    "laptop",
    "phone",
    "subsidi",
    "sumbangan",
    "rahmah",
    "emadani",
    "hadiah"
];

const PERSONAL_CONTACT_TERMS = [
    "nama penuh",
    "nombor telegram",
    "telegram",
    "whatsapp",
    "jantina",
    "no telefon",
    "nombor telefon",
    "phone number",
    "kad pengenalan",
    "identity card"
];

const SUSPICIOUS_COPY_TYPOS = [
    "securty",
    "securrity",
    "verfy",
    "verifcation",
    "verificaton",
    "accout",
    "acount",
    "passw0rd",
    "pasword",
    "logln",
    "l0gin",
    "immediatly",
    "suspention",
    "restricton",
    "unathorized",
    "aplly",
    "aply",
    "app1y",
    "appy now"
];

const HIGH_RISK_TLDS = [".click", ".online", ".site", ".top", ".xyz", ".icu", ".test"];

function toNumber(value, fallbackValue) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : fallbackValue;
}

function clampRiskScore(value) {
    return Math.max(0, Math.min(100, Math.round(value)));
}

function createLocalDecisionId() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return `local-${crypto.randomUUID()}`;
    }

    return `local-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalizeHost(rawUrl) {
    try {
        const parsed = new URL(rawUrl);
        return parsed.hostname.toLowerCase().replace(/^www\./, "");
    } catch (error) {
        return "";
    }
}

function matchesTrustedDomain(host) {
    return TRUSTED_DOMAINS.some(domain => host === domain || host.endsWith(`.${domain}`)) ||
        host.endsWith(".gov.my") ||
        host.endsWith(".edu.my");
}

function levenshteinDistance(first, second) {
    let previous = Array.from({ length: second.length + 1 }, (_, index) => index);
    let current = Array(second.length + 1).fill(0);

    for (let firstIndex = 1; firstIndex <= first.length; firstIndex += 1) {
        current[0] = firstIndex;
        for (let secondIndex = 1; secondIndex <= second.length; secondIndex += 1) {
            const substitutionCost = first[firstIndex - 1] === second[secondIndex - 1] ? 0 : 1;
            current[secondIndex] = Math.min(
                current[secondIndex - 1] + 1,
                previous[secondIndex] + 1,
                previous[secondIndex - 1] + substitutionCost
            );
        }

        [previous, current] = [current, previous];
    }

    return previous[second.length];
}

function containsNearMatch(text, target, threshold) {
    const minLength = Math.max(1, target.length - threshold);
    const maxLength = Math.min(text.length, target.length + threshold);

    for (let length = minLength; length <= maxLength; length += 1) {
        for (let index = 0; index + length <= text.length; index += 1) {
            const candidate = text.slice(index, index + length);
            if (levenshteinDistance(candidate, target) <= threshold) {
                return true;
            }
        }
    }

    return false;
}

function isPossibleBankTypo(host) {
    const simplifiedHost = host.replace(/[^a-z0-9]/g, "");

    return BANK_LOOKALIKE_TERMS.some(term => {
        if (term.length <= 4) {
            return false;
        }

        return !simplifiedHost.includes(term) && containsNearMatch(simplifiedHost, term, 2);
    });
}

function normalizeVerdictPayload(rawVerdict, scannedUrl, options = {}) {
    const rawStatus = (rawVerdict.status || rawVerdict.decision || "ALLOW").toUpperCase();
    const status = ["ALLOW", "WARN", "BLOCK"].includes(rawStatus) ? rawStatus : "WARN";
    const fallbackRisk = status === "BLOCK" ? 90 : status === "WARN" ? 58 : 18;
    const riskScore = clampRiskScore(toNumber(rawVerdict.riskScore, fallbackRisk));
    const reasons = Array.isArray(rawVerdict.reasons)
        ? rawVerdict.reasons.filter(Boolean)
        : rawVerdict.reason
            ? [rawVerdict.reason]
            : [];
    const primaryReason = reasons[0] || "No significant phishing indicators detected.";

    return {
        status,
        scannedUrl,
        domain: normalizeHost(scannedUrl) || "unknown",
        reason: primaryReason,
        reasons,
        riskScore,
        confidence: toNumber(rawVerdict.confidence, status === "BLOCK" ? 0.95 : status === "WARN" ? 0.76 : 0.92),
        decisionId: rawVerdict.decisionId || createLocalDecisionId(),
        evidenceSources: rawVerdict.evidenceSources || options.evidenceSources || "RULE_ENGINE",
        scanMode: options.scanMode || rawVerdict.scanMode || "LIVE_BACKEND",
        backendAvailable: options.backendAvailable !== false,
        scannedAt: new Date().toISOString()
    };
}

function persistLastScan(verdict) {
    chrome.storage.local.set({
        scamStatus: verdict.status,
        scamType: verdict.reason,
        lastScan: verdict
    });
}

function getTemporaryBypass(scannedUrl) {
    return new Promise(resolve => {
        chrome.storage.local.get(["temporaryBypass"], data => {
            const bypass = data.temporaryBypass;
            const bypassActive = bypass &&
                bypass.url === scannedUrl &&
                Number(bypass.expiresAt) > Date.now();

            if (!bypassActive) {
                resolve(null);
                return;
            }

            resolve(normalizeVerdictPayload({
                status: "WARN",
                riskScore: bypass.riskScore || 85,
                confidence: bypass.confidence || 0.72,
                decisionId: bypass.decisionId,
                reasons: [
                    "You chose to continue anyway. This page is still considered risky.",
                    bypass.reason || "Temporary user bypass is active for this page."
                ],
                evidenceSources: "USER_BYPASS"
            }, scannedUrl, { scanMode: "USER_BYPASS", backendAvailable: true }));
        });
    });
}

function pushBrowserNotification(verdict, force = false) {
    const isBlocked = verdict.status === "BLOCK";
    const isWarn = verdict.status === "WARN";

    if (!force && !isBlocked && !isWarn) {
        return;
    }

    const title = isBlocked
        ? "Ni Scam Ke? blocked a risky page"
        : isWarn
            ? "Ni Scam Ke? found warning signs"
            : "Ni Scam Ke? scan complete";
    const riskLabel = verdict.riskScore >= 80 ? "High" : verdict.riskScore >= 50 ? "Medium" : "Low";
    const modeLabel = verdict.backendAvailable ? "Live scan" : "Local fallback";
    const message = `${verdict.reason}\nRisk: ${riskLabel} (${verdict.riskScore}) - ${modeLabel}`;

    chrome.notifications.create({
        type: "basic",
        iconUrl: chrome.runtime.getURL("notification-icon.png"),
        title,
        message,
        priority: isBlocked ? 2 : 1
    });
}

function evaluateWithLocalRules(incomingMessage) {
    const targetUrl = incomingMessage.currentUrl || "";
    const normalizedUrl = targetUrl.toLowerCase();
    const host = normalizeHost(targetUrl);
    const pageText = (incomingMessage.pageText || "").toLowerCase();

    if (!host) {
        return normalizeVerdictPayload({
            status: "WARN",
            riskScore: 50,
            confidence: 0.6,
            reasons: ["We could not read this URL safely."],
            evidenceSources: "LOCAL_INPUT_VALIDATION"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (matchesTrustedDomain(host)) {
        return normalizeVerdictPayload({
            status: "ALLOW",
            riskScore: 12,
            confidence: 0.93,
            reasons: ["Domain matches a trusted Malaysian institution or public-interest source."],
            evidenceSources: "LOCAL_TRUST_LIST"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    const targetsBank = BANK_KEYWORDS.some(keyword => host.includes(keyword));
    const possibleBankTypo = isPossibleBankTypo(host);
    const matchedPattern = SUSPICIOUS_PATTERNS.find(pattern => normalizedUrl.includes(pattern));
    const highRiskTld = HIGH_RISK_TLDS.some(tld => host.endsWith(tld));
    const establishedMalaysianTld = host.endsWith(".my");
    const asksForSensitiveInfo = pageText.includes("otp") ||
        pageText.includes("password") ||
        pageText.includes("kata laluan") ||
        pageText.includes("verify your account");
    const hasSuspiciousCopyTypo = SUSPICIOUS_COPY_TYPOS.some(pattern => pageText.includes(pattern));
    const hasApplicationScamBait = APPLICATION_SCAM_BAIT_TERMS.some(term =>
        normalizedUrl.includes(term) || pageText.includes(term)
    );
    const collectsPersonalContact = PERSONAL_CONTACT_TERMS.some(term => pageText.includes(term));

    if (targetsBank && matchedPattern) {
        return normalizeVerdictPayload({
            status: "BLOCK",
            riskScore: 96,
            confidence: 0.94,
            reasons: [
                "This looks like a Malaysian banking lookalike domain.",
                `Matched suspicious token: ${matchedPattern}`
            ],
            evidenceSources: "LOCAL_BANK_MIMIC_RULES"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (hasApplicationScamBait && collectsPersonalContact && hasSuspiciousCopyTypo) {
        return normalizeVerdictPayload({
            status: "BLOCK",
            riskScore: 92,
            confidence: 0.9,
            reasons: [
                "This looks like a free-aid or free-device application scam.",
                "The page combines typo-filled application text with Telegram or personal-detail collection."
            ],
            evidenceSources: "LOCAL_APPLICATION_SCAM_RULES"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (hasApplicationScamBait && collectsPersonalContact) {
        return normalizeVerdictPayload({
            status: "BLOCK",
            riskScore: 85,
            confidence: 0.84,
            reasons: [
                "This page offers free aid or devices while collecting contact details on an untrusted domain.",
                "Telegram-based application flows are a common scam pattern."
            ],
            evidenceSources: "LOCAL_APPLICATION_SCAM_RULES"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (possibleBankTypo && (matchedPattern || highRiskTld || asksForSensitiveInfo)) {
        return normalizeVerdictPayload({
            status: "BLOCK",
            riskScore: 90,
            confidence: 0.9,
            reasons: [
                "This domain looks like a misspelled banking impersonation.",
                "Typo-style brand changes are common in phishing links."
            ],
            evidenceSources: "LOCAL_TYPOSQUATTING_RULES"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (hasSuspiciousCopyTypo && asksForSensitiveInfo) {
        return normalizeVerdictPayload({
            status: "WARN",
            riskScore: 75,
            confidence: 0.8,
            reasons: ["The page contains typo-heavy credential or verification language."],
            evidenceSources: "LOCAL_COPY_ANALYSIS"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (targetsBank && establishedMalaysianTld) {
        return normalizeVerdictPayload({
            status: "WARN",
            riskScore: 62,
            confidence: 0.74,
            reasons: ["This appears bank-related but is not in the trusted list yet. Verify before entering sensitive details."],
            evidenceSources: "LOCAL_REVIEW_REQUIRED"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (possibleBankTypo) {
        return normalizeVerdictPayload({
            status: "WARN",
            riskScore: 65,
            confidence: 0.76,
            reasons: ["This domain is close to a known Malaysian banking name, but is not trusted."],
            evidenceSources: "LOCAL_TYPOSQUATTING_RULES"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (targetsBank || (matchedPattern && highRiskTld)) {
        return normalizeVerdictPayload({
            status: "BLOCK",
            riskScore: 88,
            confidence: 0.88,
            reasons: ["Banking keywords or login language appear on an untrusted domain."],
            evidenceSources: "LOCAL_RISK_RULES"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    if (matchedPattern || asksForSensitiveInfo || highRiskTld) {
        return normalizeVerdictPayload({
            status: "WARN",
            riskScore: 58,
            confidence: 0.73,
            reasons: ["Some scam-like signals were found, but not enough to hard-block."],
            evidenceSources: "LOCAL_RISK_RULES"
        }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
    }

    return normalizeVerdictPayload({
        status: "ALLOW",
        riskScore: 20,
        confidence: 0.88,
        reasons: ["No suspicious URL or page-text pattern matched in local checks."],
        evidenceSources: "LOCAL_RULE_ENGINE"
    }, targetUrl, { scanMode: "LOCAL_RULES", backendAvailable: false });
}

function evaluateViaBackend(incomingMessage) {
    const structuredBackendPayload = {
        url: incomingMessage.currentUrl,
        pageText: incomingMessage.pageText,
        clientTimestamp: new Date().toISOString()
    };

    return fetch(LIVE_SCAMSHIELD_SCAN_ROUTE, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(structuredBackendPayload)
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Upstream failure: ${response.status}`);
            }
            return response.json();
        })
        .then(scanResponse => normalizeVerdictPayload(scanResponse, incomingMessage.currentUrl, {
            scanMode: "LIVE_BACKEND",
            backendAvailable: true
        }));
}

chrome.runtime.onMessage.addListener((incomingMessage, sender, dispatchVerdictCallback) => {
    if (incomingMessage.action !== "evaluateNetworkTarget") {
        return false;
    }

    const verdictPromise = getTemporaryBypass(incomingMessage.currentUrl).then(bypassVerdict => {
        if (bypassVerdict) {
            return bypassVerdict;
        }

        return LIVE_BACKEND_ENABLED
            ? evaluateViaBackend(incomingMessage).catch(error => {
                console.warn("[Ni Scam Ke] Backend unavailable, using local fallback:", error);
                const fallbackVerdict = evaluateWithLocalRules(incomingMessage);
                return {
                    ...fallbackVerdict,
                    reasons: [
                        "Live protection service is offline, so local safety checks were used.",
                        ...fallbackVerdict.reasons
                    ],
                    reason: "Live protection service is offline, so local safety checks were used.",
                    scanMode: "LOCAL_FALLBACK",
                    backendAvailable: false
                };
            })
            : evaluateWithLocalRules(incomingMessage);
    });

    verdictPromise
        .then(verdict => {
            persistLastScan(verdict);
            pushBrowserNotification(verdict);
            dispatchVerdictCallback(verdict);
        })
        .catch(error => {
            console.error("[Ni Scam Ke] Scan pipeline error:", error);

            const safeFallbackVerdict = normalizeVerdictPayload({
                status: "WARN",
                riskScore: 50,
                confidence: 0.55,
                reasons: ["Protection status is uncertain. Avoid entering passwords or OTPs here."],
                evidenceSources: "FAILSAFE"
            }, incomingMessage.currentUrl, { scanMode: "FAILSAFE", backendAvailable: false });

            persistLastScan(safeFallbackVerdict);
            dispatchVerdictCallback(safeFallbackVerdict);
        });

    return true;
});
