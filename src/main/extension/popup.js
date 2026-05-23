const STATE_COPY = {
    ALLOW: {
        title: "Looks safe",
        subtitle: "Laman ini nampak selamat. Keep an eye out before entering sensitive details."
    },
    WARN: {
        title: "Use caution",
        subtitle: "Ada tanda mencurigakan. Avoid entering passwords, OTPs, or payment details."
    },
    USER_BYPASS: {
        title: "Bypassed warning",
        subtitle: "You continued at your own risk. This page is still considered suspicious."
    },
    BLOCK: {
        title: "High-risk page",
        subtitle: "Kami berhentikan laman ini kerana ia menyerupai cubaan scam atau phishing."
    },
    WAITING: {
        title: "Protection is active",
        subtitle: "Open any page and Ni Scam Ke? will check it automatically."
    },
    SCANNING: {
        title: "Refreshing now",
        subtitle: "Checking this tab again with Ni Scam Ke? protection."
    }
};

function formatPercent(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
        return "--";
    }

    return `${Math.round(numeric * 100)}%`;
}

function formatMode(scan) {
    if (!scan) {
        return "Not scanned";
    }

    if (scan.backendAvailable === false) {
        return "Local fallback";
    }

    return scan.scanMode === "LIVE_BACKEND" ? "Live backend" : scan.scanMode || "Live backend";
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
    const status = (scan?.status || "WAITING").toUpperCase();
    const displayStatus = scan?.scanMode === "USER_BYPASS" ? "USER_BYPASS" : status;
    const copy = STATE_COPY[displayStatus] || STATE_COPY.WAITING;
    const riskScore = Number.isFinite(Number(scan?.riskScore)) ? Number(scan.riskScore) : 0;
    const reason = scan?.reason || "No scan result yet. Visit a page or refresh protection status for this tab.";

    setCardState(displayStatus);

    document.getElementById("statusTitle").textContent = copy.title;
    document.getElementById("statusSubtitle").textContent = copy.subtitle;
    document.getElementById("riskScore").textContent = scan ? `${Math.round(riskScore)}/100` : "--/100";
    document.getElementById("riskFill").style.width = scan ? `${Math.max(0, Math.min(100, riskScore))}%` : "0%";
    document.getElementById("decisionLabel").textContent = scan ? displayStatus : "Waiting";
    document.getElementById("confidenceLabel").textContent = formatPercent(scan?.confidence);
    document.getElementById("modeLabel").textContent = formatMode(scan);
    document.getElementById("domainLabel").textContent = scan?.domain || "Current tab";
    document.getElementById("reasonText").textContent = reason;
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
        button.textContent = "Refreshing this tab...";
        button.disabled = true;
        renderPopup({
            status: "SCANNING",
            riskScore: 50,
            confidence: 0.5,
            domain: "Refreshing",
            reason: "Asking the page scanner to refresh the current tab status.",
            scanMode: "SCANNING",
            backendAvailable: true
        });

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
