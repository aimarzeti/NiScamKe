(function () {
    const activeWebUrl = window.location.href;
    const SENSITIVE_FIELD_PATTERN = /(otp|tac|pin|password|passcode|fpx|card|kad|ic|mykad|kata\s*laluan|nombor\s*telefon|phone)/i;
    let activePageScanPromise = null;
    let credentialGuardTriggered = false;

    if (activeWebUrl.startsWith("chrome://") || activeWebUrl.startsWith("chrome-extension://")) {
        return;
    }

    function normalizeTargetUrl(rawUrl) {
        try {
            return new URL(rawUrl, window.location.href).href;
        } catch (error) {
            return "";
        }
    }

    function isHttpTarget(rawUrl) {
        try {
            const parsedUrl = new URL(rawUrl, window.location.href);
            return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
        } catch (error) {
            return false;
        }
    }

    function buildBlockedPageUrl(verdict, blockedUrl = activeWebUrl) {
        const params = new URLSearchParams();
        params.set("blocked", blockedUrl);

        if (verdict.reason) {
            params.set("reason", verdict.reason);
        }

        if (typeof verdict.riskScore === "number") {
            params.set("riskScore", String(verdict.riskScore));
        }

        if (typeof verdict.confidence === "number") {
            params.set("confidence", String(verdict.confidence));
        }

        if (Array.isArray(verdict.reasons) && verdict.reasons.length > 0) {
            params.set("reasons", JSON.stringify(verdict.reasons.slice(0, 5)));
        }

        if (verdict.evidenceSources) {
            params.set("sources", verdict.evidenceSources);
        }

        return `${chrome.runtime.getURL("blocked.html")}?${params.toString()}`;
    }

    function getVisiblePageText(extraText = "") {
        const visibleViewportText = document.body ? document.body.innerText : "";
        return `${visibleViewportText} ${extraText}`.trim().substring(0, 2400);
    }

    function requestNetworkVerdict(targetUrl, options = {}) {
        const validationPayload = {
            action: "evaluateNetworkTarget",
            currentUrl: targetUrl,
            pageText: options.pageText || getVisiblePageText(options.extraText),
            credentialFieldDetected: options.credentialFieldDetected === true,
            credentialFieldLabel: options.credentialFieldLabel || "",
            forceNotification: options.forceNotification === true
        };

        return new Promise(resolve => {
            chrome.runtime.sendMessage(validationPayload, verdict => {
                if (chrome.runtime.lastError) {
                    resolve(null);
                    return;
                }

                resolve(verdict || null);
            });
        });
    }

    function scanActiveDocumentContext(options = {}) {
        if (activePageScanPromise && !options.force) {
            return activePageScanPromise;
        }

        activePageScanPromise = requestNetworkVerdict(activeWebUrl, {
            pageText: getVisiblePageText(options.extraText),
            credentialFieldDetected: options.credentialFieldDetected === true,
            credentialFieldLabel: options.credentialFieldLabel || "",
            forceNotification: options.forceNotification === true
        }).then(verdict => {
            activePageScanPromise = null;

            if (verdict && verdict.status === "BLOCK") {
                const blockedPageUrl = buildBlockedPageUrl(verdict, activeWebUrl);
                window.location.replace(blockedPageUrl);
            }

            return verdict;
        });

        return activePageScanPromise;
    }

    function findAnchor(target) {
        const element = target instanceof Element ? target : target && target.parentElement;
        return element ? element.closest("a[href]") : null;
    }

    function shouldScanClickedLink(event, anchor, targetUrl) {
        if (!anchor || event.defaultPrevented || event.button !== 0) {
            return false;
        }

        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || anchor.hasAttribute("download")) {
            return false;
        }

        if (!isHttpTarget(targetUrl)) {
            return false;
        }

        try {
            const current = new URL(activeWebUrl);
            const target = new URL(targetUrl);
            const sameDocumentHashNavigation = current.origin === target.origin &&
                current.pathname === target.pathname &&
                current.search === target.search &&
                target.hash;

            return !sameDocumentHashNavigation;
        } catch (error) {
            return true;
        }
    }

    function continueToScannedLink(anchor, targetUrl) {
        if (anchor.target && anchor.target.toLowerCase() === "_blank") {
            window.open(targetUrl, "_blank", "noopener");
            return;
        }

        window.location.href = targetUrl;
    }

    async function scanLinkBeforeNavigation(event) {
        const anchor = findAnchor(event.target);
        const targetUrl = normalizeTargetUrl(anchor ? anchor.href : "");

        if (!shouldScanClickedLink(event, anchor, targetUrl)) {
            return;
        }

        event.preventDefault();
        event.stopImmediatePropagation();

        const linkText = [
            anchor.innerText,
            anchor.getAttribute("aria-label"),
            anchor.title,
            targetUrl
        ].filter(Boolean).join(" ");

        const verdict = await requestNetworkVerdict(targetUrl, {
            pageText: linkText.substring(0, 1200)
        });

        if (verdict && verdict.status === "BLOCK") {
            window.location.href = buildBlockedPageUrl(verdict, targetUrl);
            return;
        }

        continueToScannedLink(anchor, targetUrl);
    }

    function isSensitiveField(target) {
        if (!(target instanceof HTMLInputElement) && !(target instanceof HTMLTextAreaElement)) {
            return false;
        }

        const type = (target.getAttribute("type") || "").toLowerCase();
        const fieldText = [
            type,
            target.name,
            target.id,
            target.placeholder,
            target.getAttribute("aria-label"),
            target.autocomplete
        ].filter(Boolean).join(" ");

        return type === "password" || SENSITIVE_FIELD_PATTERN.test(fieldText);
    }

    function describeSensitiveField(target) {
        return [
            target.getAttribute("type"),
            target.name,
            target.id,
            target.placeholder,
            target.getAttribute("aria-label"),
            target.autocomplete
        ].filter(Boolean).join(" ");
    }

    function handleCredentialFieldFocus(event) {
        if (credentialGuardTriggered || !isSensitiveField(event.target)) {
            return;
        }

        credentialGuardTriggered = true;
        const credentialFieldLabel = describeSensitiveField(event.target);
        scanActiveDocumentContext({
            force: true,
            credentialFieldDetected: true,
            credentialFieldLabel,
            extraText: `Sensitive credential field focused: ${credentialFieldLabel}`
        });
    }

    document.addEventListener("click", scanLinkBeforeNavigation, true);
    document.addEventListener("focusin", handleCredentialFieldFocus, true);

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (!message || message.action !== "scanCurrentPageNow") {
            return false;
        }

        scanActiveDocumentContext({ force: true, forceNotification: true }).then(verdict => {
            sendResponse({ ok: true, verdict });
        });

        return true;
    });

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", scanActiveDocumentContext);
    } else {
        scanActiveDocumentContext();
    }
})();
