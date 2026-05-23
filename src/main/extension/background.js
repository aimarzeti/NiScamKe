/**
 * ScamShield AI - Background Service Worker (Traffic Router)
 * Core background controller for routing network traffic to the Spring Boot analytics server.
 */

// ======================================================================
// CONFIGURATION UNIT
// ======================================================================

// Set to false to disable local sandbox mock mode and enable live communication with the Spring Boot backend
const MOCK_MODE = false; 

// Upstream target route for the Spring Boot REST framework API verification endpoint
const LIVE_SCAMSHIELD_API_ROUTE = "http://localhost:8080/api/v1/verify-link"; 

chrome.runtime.onMessage.addListener((incomingMessage, sender, dispatchVerdictCallback) => {
    
    if (incomingMessage.action === "evaluateNetworkTarget") {
        const targetUrl = incomingMessage.currentUrl.toLowerCase();

        // ------------------------------------------------------------------
        // SANDBOX SCENARIO RUNTIME (Executes only if MOCK_MODE is true)
        // ------------------------------------------------------------------
        if (MOCK_MODE) {
            console.log(`[ScamShield Sandbox Demo] Inspecting target: ${targetUrl}`);

            // Verified official domains for major financial institutions in Malaysia
            const trustedDomains = [
                "maybank2u.com.my", 
                "maybank.com", 
                "cimb.com.my", 
                "cimbclicks.com.my",
                "hongleongbank.com.my", 
                "hlb.com.my",
                "pbebank.com", 
                "publicbank.com.my",
                "bankislam.com.my", 
                "thijari.com.my",
                "muamalat.com.my",
                "rhbgroup.com",
                "ambankamonline.com",
                "alliancebank.com.my",
                "bsn.com.my",
                "affinalways.com",
                "uob.com.my",
                "ocbc.com.my",
                "hsbc.com.my",
                "sc.com/my"
            ];

            // Evaluate if target URL belongs to a verified official system domain
            const isTrusted = trustedDomains.some(domain => targetUrl.includes(domain));

            // Known string structures frequently deployed by malicious syndicates
            const suspiciousPatterns = [
                "secure-login",
                "verify-account",
                "account-suspended",
                "login-update",
                "bank-verification",
                "maybank-secure",
                "cimb-secure",
                "bankislam-secure",
                "thijari-secure",
                "muamalat-secure"
            ];

            const isSuspicious = suspiciousPatterns.some(pattern => targetUrl.includes(pattern));

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
        // PRODUCTION OPERATION ROUTE (Streams data live to Spring Boot)
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
            // Relays production verification status ("BLOCK" / "ALLOW") down to content script
            dispatchVerdictCallback({ status: verdictDataContract.status });
        })
        .catch(error => {
            console.error("[ScamShield Network Fault] Direct routing error:", error);
            // Fallback protocol: Prevent browser isolation if cloud server is temporarily unreachable
            dispatchVerdictCallback({ status: "ALLOW" });
        });

        return true; 
    }
});