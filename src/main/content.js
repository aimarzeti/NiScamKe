/**
 * ScamShield AI - Content Script (Layer 1 Active Sensor)
 * Matches Diagram: Reads active page text and intercepts the page session if a threat is verified.
 */
(function () {
    const activeWebUrl = window.location.href;

    // Avoid running on internal browser configuration pathways
    if (activeWebUrl.startsWith("chrome://") || activeWebUrl.startsWith("chrome-extension://")) {
        return;
    }

    function scanActiveDocumentContext() {
        // Reads active page visible text content parameters up to 1000 characters
        const visibleViewportText = document.body ? document.body.innerText.substring(0, 1000) : "";

        const validationPayload = {
            action: "evaluateNetworkTarget",
            currentUrl: activeWebUrl,
            pageText: visibleViewportText
        };

        // Dispatch telemetry metrics up to the background processor line
        chrome.runtime.sendMessage(validationPayload, (backendServerVerdict) => {
            if (chrome.runtime.lastError) {
                return;
            }

            // DIAGRAM FLOW EXECUTION: If verdict state evaluates to BLOCK, immediately render the protection screen
            if (backendServerVerdict && backendServerVerdict.status === "BLOCK") {
                console.warn("🚨 [ScamShield AI] Threat Verified! Diverting session away from scam page...");
                window.location.href = chrome.runtime.getURL("blocked.html");
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", scanActiveDocumentContext);
    } else {
        scanActiveDocumentContext();
    }
})();