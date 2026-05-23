(function () {
    const activeWebUrl = window.location.href;

    if (activeWebUrl.startsWith("chrome://") || activeWebUrl.startsWith("chrome-extension://")) {
        return;
    }

    function scanActiveDocumentContext() {
        const visibleViewportText = document.body ? document.body.innerText.substring(0, 1000) : "";

        const validationPayload = {
            action: "evaluateNetworkTarget",
            currentUrl: activeWebUrl,
            pageText: visibleViewportText
        };

        chrome.runtime.sendMessage(validationPayload, (backendServerVerdict) => {
            if (chrome.runtime.lastError) {
                return;
            }

            if (backendServerVerdict && backendServerVerdict.status === "BLOCK") {
                console.warn("🚨 [ScamShield AI] Threat Verified! Diverting session...");
                // ✅ FIX: Pass the original URL as a query parameter
                const blockedPageUrl = chrome.runtime.getURL("blocked.html") +
                    "?blocked=" + encodeURIComponent(activeWebUrl);
                window.location.href = blockedPageUrl;
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", scanActiveDocumentContext);
    } else {
        scanActiveDocumentContext();
    }
})();