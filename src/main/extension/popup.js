const STATE_COPY = {
    ALLOW: {
        title: "Looks safe",
        subtitle: "This site looks safe. Keep an eye out before entering sensitive details."
    },
    WARN: {
        title: "Use caution",
        subtitle: "This site has suspicious elements. Avoid entering passwords, OTPs, or payment details."
    },
    USER_BYPASS: {
        title: "Bypassed warning",
        subtitle: "You continued at your own risk. This page is still considered suspicious."
    },
    BLOCK: {
        title: "High-risk page",
        subtitle: "This page is considered high-risk because it exhibits characteristics associated with scams or phishing attempts. We have blocked it to protect you."
    },
    WAITING: {
        title: "Ready to scan",
        subtitle: "Open a page or scan the current tab to see the latest protection signal."
    },
    SCANNING: {
        title: "Scanning now",
        subtitle: "Checking the current page with Ni Scam Ke? protection."
    }
};

let renderSequence = 0;

function formatPercent(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
        return "--";
    }

    return `${Math.round(numeric * 100)}%`;
}

function formatMode(scan) {
    if (!scan) {
        return UI_COPY.notScanned;
    }

    if (scan.backendAvailable === false) {
        return scan.scanMode === "LOCAL_RULES" ? "Local scam rules" : UI_COPY.localFallback;
    }

    return scan.scanMode === "LIVE_BACKEND" ? UI_COPY.liveBackend : scan.scanMode || UI_COPY.liveBackend;
}

function setCardState(status) {
    const card = document.querySelector(".hero-card");
    card.classList.remove("state-allow", "state-warn", "state-block");

    if (status === "ALLOW") {
        card.classList.add("state-allow");
    } else if (status === "WARN" || status === "USER_BYPASS") {
        card.classList.add("state-warn");
    } else if (status === "BLOCK") {
        card.classList.add("state-block");
    }
}

function renderPopup(scan) {
    const currentRender = ++renderSequence;
    const status = (scan?.status || "WAITING").toUpperCase();
    const displayStatus = scan?.scanMode === "USER_BYPASS" ? "USER_BYPASS" : status;
    const copy = UI_COPY.states[displayStatus] || UI_COPY.states.WAITING;
    const riskScore = Number.isFinite(Number(scan?.riskScore)) ? Number(scan.riskScore) : 0;
    const reason = scan?.reason || "No scan result yet. Click scan to refresh the current page.";

    setCardState(displayStatus);

    document.getElementById("riskScoreLabel").textContent = UI_COPY.riskScoreLabel;
    document.getElementById("statusLabel").textContent = UI_COPY.statusLabel;
    document.getElementById("confidenceTitle").textContent = UI_COPY.confidenceTitle;
    document.getElementById("modeTitle").textContent = UI_COPY.modeTitle;
    document.getElementById("domainTitle").textContent = UI_COPY.domainTitle;
    document.getElementById("whyLabel").textContent = displayStatus === "ALLOW"
        ? UI_COPY.safeReminderLabel
        : UI_COPY.whyLabel;
    document.getElementById("privacyNote").textContent = UI_COPY.privacyNote;

    const scanButton = document.getElementById("scanButton");
    if (!scanButton.disabled) {
        scanButton.textContent = UI_COPY.scanButton;
    }

    document.getElementById("statusTitle").textContent = copy.title;
    document.getElementById("statusSubtitle").textContent = copy.subtitle;
    document.getElementById("riskScore").textContent = scan ? `${Math.round(riskScore)}/100` : "--/100";
    document.getElementById("riskFill").style.width = scan ? `${Math.max(0, Math.min(100, riskScore))}%` : "0%";
    document.getElementById("decisionLabel").textContent = scan ? displayStatus : UI_COPY.waitingDecision;
    document.getElementById("confidenceLabel").textContent = formatPercent(scan?.confidence);
    document.getElementById("modeLabel").textContent = formatMode(scan);
    document.getElementById("domainLabel").textContent = scan?.domain || UI_COPY.currentTab;
    document.getElementById("reasonText").textContent = displayStatus === "ALLOW"
        ? UI_COPY.safeReminder
        : displayStatus === "USER_BYPASS"
            ? "You chose to continue anyway. This website might be a scam, so stay alert and avoid entering sensitive information."
            : reason;
}

function refreshPopupState() {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        const activeTab = tabs && tabs.length > 0 ? tabs[0] : null;

        chrome.storage.local.get(["lastScan", "scanByTab"], data => {
            const tabScan = activeTab && activeTab.id && data.scanByTab
                ? data.scanByTab[String(activeTab.id)]
                : null;

            renderPopup(tabScan || data.lastScan);
        });
    });
}

function bindScanButton() {
    const button = document.getElementById("scanButton");

    button.addEventListener("click", () => {
        const originalText = button.textContent;
        button.textContent = "Scanning current tab...";
        button.disabled = true;
        renderPopup({
            status: "SCANNING",
            riskScore: 50,
            confidence: 0.5,
            domain: "Refreshing",
            reason: "Refreshing the tab so the content scanner can evaluate the latest page.",
            scanMode: "SCANNING",
            backendAvailable: true
        });
        button.textContent = UI_COPY.scanButtonLoading;

        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs && tabs.length > 0 && tabs[0].id) {
                chrome.tabs.sendMessage(tabs[0].id, { action: "scanCurrentPageNow" }, () => {
                    const ignoredLastError = chrome.runtime.lastError;
                    setTimeout(() => {
                        button.textContent = originalText;
                        button.disabled = false;
                        refreshPopupState();
                    }, 500);
                });
                return;
            }

            [900, 1800, 3200].forEach(delay => {
                setTimeout(refreshPopupState, delay);
            });

            setTimeout(() => {
                button.textContent = originalText;
                button.disabled = false;
                refreshPopupState();
            }, 1600);
        });
    });
}

document.addEventListener("DOMContentLoaded", () => {
    refreshPopupState();
    bindScanButton();
});
