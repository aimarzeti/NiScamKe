/**
 * ScamShield AI - Background Service Worker (Traffic Router)
 * Core background controller for routing network traffic to the Spring Boot analytics server.
 */

// ======================================================================
// CONFIGURATION UNIT
// ======================================================================

// Set to true to enable local sandbox mock mode; set to false to route to the live backend.
const MOCK_MODE = true;

// Upstream target route for the Spring Boot REST framework API verification endpoint
const LIVE_SCAMSHIELD_API_ROUTE = "http://localhost:8080/api/v1/verify-link";

chrome.runtime.onMessage.addListener((incomingMessage, sender, dispatchVerdictCallback) => {
    if (incomingMessage.action === "evaluateNetworkTarget") {
        const targetUrl = incomingMessage.currentUrl.toLowerCase();

        if (MOCK_MODE) {
            console.log(`[ScamShield Sandbox Demo] Inspecting target: ${targetUrl}`);

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
            const isSuspicious = suspiciousPatterns.some(pattern => targetUrl.includes(pattern));

            if (isTrusted) {
                chrome.storage.local.set({ scamStatus: "ALLOW", scamType: "Official trusted domain" });
                dispatchVerdictCallback({ status: "ALLOW" });
            } else if (isSuspicious) {
                chrome.storage.local.set({ scamStatus: "BLOCK", scamType: "Bank Impersonation Scam" });
                dispatchVerdictCallback({ status: "BLOCK" });
            } else {
                chrome.storage.local.set({ scamStatus: "ALLOW", scamType: "None Detected" });
                dispatchVerdictCallback({ status: "ALLOW" });
            }

            return true;
        }

        const structuredBackendPayload = {
            currentUrl: incomingMessage.currentUrl,
            pageText: incomingMessage.pageText
        };

        fetch(LIVE_SCAMSHIELD_API_ROUTE, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(structuredBackendPayload)
        })
        .then(response => {
            if (!response.ok) throw new Error(`Upstream failure: ${response.status}`);
            return response.json();
        })
        .then(verdictDataContract => {
            dispatchVerdictCallback({ status: verdictDataContract.status });
        })
        .catch(error => {
            console.error("[ScamShield Network Fault] Direct routing error:", error);
            dispatchVerdictCallback({ status: "ALLOW" });
        });

        return true;
    }
});