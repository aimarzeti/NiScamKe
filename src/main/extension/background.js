/**
 * ScamShield AI - Background Service Worker (Traffic Router)
 * Matches Diagram: Routes telemetry payloads to Render or executes controlled sandbox scenario mocks.
 */

// ======================================================================
// 🎛️ LIVE DEMO CONTROL UNIT
// ======================================================================
// Set to true: Extension mocks backend responses locally for live stage presentations.
// Set to false: Extension routes data streams live to Person 1's Spring Boot Render server.
const MOCK_MODE = true; 

// Upstream target route allocated for Person 1's Spring Boot REST framework configuration
const LIVE_SCAMSHIELD_API_ROUTE = "http://localhost:8080/api/v1/verify-link";

chrome.runtime.onMessage.addListener((incomingMessage, sender, dispatchVerdictCallback) => {
    
    if (incomingMessage.action === "evaluateNetworkTarget") {
        const targetUrl = incomingMessage.currentUrl.toLowerCase();

        // ------------------------------------------------------------------
        // SANDBOX SCENARIO RUNTIME (Runs instantly if MOCK_MODE is enabled)
        // ------------------------------------------------------------------
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
                "publicbank.com.my", 
                "bankislam.com.my"
            ];

            const isTrusted = trustedDomains.some(domain => targetUrl.contains(domain)
            );

            const suspiciousPatterns = [
                "secure-login",
                "verify-account",
                "account-suspended",
                "login-update",
                "bank-verification",
                "maybank-secure",
                "cimb-secure",
                "bankislam-secure",
            ];

            const isSuspicious = suspiciousPatterns.some(pattern => targetUrl.contains(pattern)
            );

           if (isTrusted) {
            chrome.storage.local.set({
                scamStatus: "ALLOW",
                scamType: "Official trusted domain"
            });

            dispatchVerdictCallback({ status: "ALLOW" });

        } else if (isSuspicious) {
            chrome.storage.local.set({ 
                scamStatus: "BLOCK", 
                scamType: "Bank Impersonation Scam" 
            });

            dispatchVerdictCallback({ status: "BLOCK" });

        } else {
            chrome.storage.local.set({
                scamStatus: "ALLOW", 
                scamType: "None Detected" 
            });

            dispatchVerdictCallback({ status: "ALLOW" });
        }
            return true;

        }

        // ------------------------------------------------------------------
        // PRODUCTION OPERATION ROUTE (Fires live payload streams to Render)
        // ------------------------------------------------------------------
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
            if (!response.ok) throw new Error(`Upstream system response failure: ${response.status}`);
            return response.json();
        })
        .then(verdictDataContract => {
            // Relays production response structure ("BLOCK" / "ALLOW") down to content script line
            dispatchVerdictCallback({ status: verdictDataContract.status });
        })
        .catch(error => {
            console.error("[ScamShield Network Fault] Direct routing error:", error);
            // Fallback protocol: Keep internet open if cloud infrastructure is unreachable
            dispatchVerdictCallback({ status: "ALLOW" });
        });

        return true; 
    }
});

// Helper polyfill mapping for standard evaluation utilities inside older worker states
if (!String.prototype.contains) {
    String.prototype.contains = function(arg) {
        return this.indexOf(arg) !== -1;
    };
}