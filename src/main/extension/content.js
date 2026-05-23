(function () {
    const activeWebUrl = window.location.href;

    if (activeWebUrl.startsWith("chrome://") || activeWebUrl.startsWith("chrome-extension://")) {
        return;
    }

    function buildBlockedPageUrl(verdict) {
        const params = new URLSearchParams();
        params.set("blocked", activeWebUrl);

        if (verdict.reason) {
            params.set("reason", verdict.reason);
        }

        if (typeof verdict.riskScore === "number") {
            params.set("riskScore", String(verdict.riskScore));
        }

        if (typeof verdict.confidence === "number") {
            params.set("confidence", String(verdict.confidence));
        }

        if (verdict.decisionId) {
            params.set("decisionId", verdict.decisionId);
        }

        if (Array.isArray(verdict.reasons) && verdict.reasons.length > 0) {
            params.set("reasons", JSON.stringify(verdict.reasons.slice(0, 5)));
        }

        if (verdict.evidenceSources) {
            params.set("sources", verdict.evidenceSources);
        }

        return `${chrome.runtime.getURL("blocked.html")}?${params.toString()}`;
    }

    function scanActiveDocumentContext() {
        const visibleViewportText = document.body ? document.body.innerText.substring(0, 2000) : "";

        const validationPayload = {
            action: "evaluateNetworkTarget",
            currentUrl: activeWebUrl,
            pageText: visibleViewportText
        };

        chrome.runtime.sendMessage(validationPayload, verdict => {
            if (chrome.runtime.lastError) {
                return;
            }

            if (verdict && verdict.status === "BLOCK") {
                const blockedPageUrl = buildBlockedPageUrl(verdict);
                window.location.replace(blockedPageUrl);
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", scanActiveDocumentContext);
    } else {
        scanActiveDocumentContext();
    }
})();
