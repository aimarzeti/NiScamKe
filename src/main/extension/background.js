/**
 * Ni Scam Ke? - Background Service Worker
 * Evaluates URLs, stores scan context, and sends browser notifications.
 */

const MOCK_MODE = true;
const LIVE_SCAMSHIELD_SCAN_ROUTE = "http://localhost:8080/api/v1/scan-url";

function toNumber(value, fallbackValue) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : fallbackValue;
}

function normalizeVerdictPayload(rawVerdict, scannedUrl) {
    const status = (rawVerdict.status || rawVerdict.decision || "ALLOW").toUpperCase();
    const reasons = Array.isArray(rawVerdict.reasons)
        ? rawVerdict.reasons.filter(Boolean)
        : rawVerdict.reason
            ? [rawVerdict.reason]
            : [];
    const primaryReason = reasons[0] || "No significant phishing indicators detected.";

    return {
        status,
        scannedUrl,
        reason: primaryReason,
        reasons,
        riskScore: toNumber(rawVerdict.riskScore, status === "BLOCK" ? 90 : 20),
        confidence: toNumber(rawVerdict.confidence, status === "BLOCK" ? 0.95 : 0.92),
        decisionId: rawVerdict.decisionId || "",
        evidenceSources: rawVerdict.evidenceSources || "RULE_ENGINE",
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

function pushBrowserNotification(verdict, force = false) {
    const isBlocked = verdict.status === "BLOCK";
    const isWarn = verdict.status === "WARN";

    if (!force && !isBlocked && !isWarn) {
        return;
    }

    const title = isBlocked
        ? "Ni Scam Ke? Alert"
        : isWarn
            ? "Ni Scam Ke? Warning"
            : "Ni Scam Ke? Scan Complete";
    const riskLabel = verdict.riskScore >= 80 ? "High" : verdict.riskScore >= 50 ? "Medium" : "Low";
    const message = `${verdict.reason}\nRisk: ${riskLabel} (${verdict.riskScore})`;

    chrome.notifications.create({
        type: "basic",
        iconUrl: chrome.runtime.getURL("notification-icon.png"),
        title,
        message,
        priority: isBlocked ? 2 : 1
    });
}

function evaluateInMockMode(incomingMessage) {
    const targetUrl = incomingMessage.currentUrl.toLowerCase();

    const trustedDomains = [
        "maybank2u.com.my",
        "maybank.com",
        "cimb.com.my",
        "hongleongbank.com.my",
        "pbebank.com",
        "rytbank.my",
        "bankislam.com.my",
        "publicbank.com.my"
    ];

    const suspiciousPatterns = [
        "secure-login",
        "verify-account",
        "account-suspended",
        "login-update",
        "bank-verification",
        "maybank-secure",
        "cimb-secure",
        "bankislam-secure"
    ];

    const isTrustedDomain = trustedDomains.some(domain => targetUrl.includes(domain));
    const isTrustedTLD = targetUrl.includes(".com.my") ||
        targetUrl.includes(".gov.my") ||
        targetUrl.includes(".edu.my") ||
        targetUrl.includes(".org.my");
    const isTrusted = isTrustedDomain || isTrustedTLD;

    const matchedPattern = suspiciousPatterns.find(pattern => targetUrl.includes(pattern));
    const isSuspicious = Boolean(matchedPattern);

    if (isTrusted) {
        return normalizeVerdictPayload({
            status: "ALLOW",
            riskScore: 15,
            confidence: 0.94,
            reasons: ["Domain and TLD match trusted Malaysian sources."],
            evidenceSources: "MOCK_RULE_ENGINE"
        }, incomingMessage.currentUrl);
    }

    if (isSuspicious) {
        return normalizeVerdictPayload({
            status: "BLOCK",
            riskScore: 92,
            confidence: 0.97,
            reasons: [
                "URL pattern matches known credential-harvesting behavior.",
                `Matched suspicious token: ${matchedPattern}`
            ],
            evidenceSources: "MOCK_RULE_ENGINE"
        }, incomingMessage.currentUrl);
    }

    return normalizeVerdictPayload({
        status: "ALLOW",
        riskScore: 24,
        confidence: 0.9,
        reasons: ["No suspicious lexical pattern matched in URL."],
        evidenceSources: "MOCK_RULE_ENGINE"
    }, incomingMessage.currentUrl);
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
        .then(scanResponse => normalizeVerdictPayload(scanResponse, incomingMessage.currentUrl));
}

chrome.runtime.onMessage.addListener((incomingMessage, sender, dispatchVerdictCallback) => {
    if (incomingMessage.action === "evaluateNetworkTarget") {
        const verdictPromise = MOCK_MODE
            ? Promise.resolve(evaluateInMockMode(incomingMessage))
            : evaluateViaBackend(incomingMessage);

        verdictPromise
            .then(verdict => {
                persistLastScan(verdict);
                pushBrowserNotification(verdict);
                dispatchVerdictCallback(verdict);
            })
            .catch(error => {
                console.error("[Ni Scam Ke] Scan pipeline error:", error);

                const fallbackVerdict = normalizeVerdictPayload({
                    status: "ALLOW",
                    riskScore: 35,
                    confidence: 0.55,
                    reasons: ["Scan service unavailable, fail-open policy applied."],
                    evidenceSources: "FAILSAFE"
                }, incomingMessage.currentUrl);

                persistLastScan(fallbackVerdict);
                dispatchVerdictCallback(fallbackVerdict);
            });

        return true;
    }

    if (incomingMessage.action === "triggerDemoNotification") {
        const demoStatus = incomingMessage.status === "BLOCK" ? "BLOCK" : "ALLOW";

        const demoVerdict = normalizeVerdictPayload({
            status: demoStatus,
            riskScore: demoStatus === "BLOCK" ? 91 : 18,
            confidence: demoStatus === "BLOCK" ? 0.96 : 0.93,
            reasons: [
                demoStatus === "BLOCK"
                    ? "Demo alert triggered for judge walkthrough."
                    : "Demo safe scan triggered for judge walkthrough."
            ],
            evidenceSources: "DEMO"
        }, incomingMessage.currentUrl || "https://demo.local");

        persistLastScan(demoVerdict);
        pushBrowserNotification(demoVerdict, true);
        dispatchVerdictCallback({ ok: true });
        return true;
    }
});

