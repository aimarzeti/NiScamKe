const UI_COPY = {
    riskScoreLabel: "Risk score",
    statusLabel: "Status",
    confidenceTitle: "Confidence",
    modeTitle: "Mode",
    domainTitle: "Domain",
    whyLabel: "Why blocked",
    safeReminderLabel: "Stay alert",
    safeReminder: "This page looks safe, but always check the URL and avoid entering sensitive details unless you fully trust the site.",
    privacyNote: "Privacy note: Ni Scam Ke? never asks for passwords, OTPs, or banking credentials.",
    scanButton: "Scan Current Page",
    scanButtonLoading: "Scanning current tab...",
    waitingDecision: "Waiting",
    currentTab: "Current tab",
    notScanned: "Not scanned",
    liveBackend: "Live backend + Gemini AI",
    localFallback: "Backend unavailable",
    reasonFallback: "No scan result yet. Click scan to refresh the current page.",
    refreshingReason: "Refreshing the tab so the live backend and Gemini AI can evaluate the latest page.",
    states: {
        ALLOW: {
            title: "Looks safe",
            subtitle: "This page looks safe. Stay alert before entering sensitive details."
        },
        WARN: {
            title: "Use caution",
            subtitle: "Suspicious signs were found. Avoid entering passwords, OTPs, or payment details."
        },
        USER_BYPASS: {
            title: "This website might be a scam!",
            subtitle: "You chose to continue anyway. Be careful and do not enter passwords, OTPs, payment details, or personal information unless you fully trust this site."
        },
        BLOCK: {
            title: "This is a scam!",
            subtitle: "We stopped this page because Gemini AI and the live backend found scam or phishing signals."
        },
        WAITING: {
            title: "Ready to scan",
            subtitle: "Open a page or scan the current tab to see the latest protection signal."
        },
        SCANNING: {
            title: "Scanning now",
            subtitle: "Checking the current page with the live backend and Gemini AI."
        }
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
    const reason = scan?.reason || UI_COPY.reasonFallback;

    if (currentRender !== renderSequence) {
        return;
    }

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
    chrome.storage.local.get(["lastScan"], data => {
        renderPopup(data.lastScan);
    });
}

function bindScanButton() {
    const button = document.getElementById("scanButton");

    button.addEventListener("click", () => {
        const originalText = button.textContent;
        button.textContent = UI_COPY.scanButtonLoading;
        button.disabled = true;
        renderPopup({
            status: "SCANNING",
            riskScore: 50,
            confidence: 0.5,
            domain: "Refreshing",
            reason: UI_COPY.refreshingReason,
            scanMode: "SCANNING",
            backendAvailable: true
        });
        button.textContent = UI_COPY.scanButtonLoading;

        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs && tabs.length > 0 && tabs[0].id) {
                chrome.tabs.reload(tabs[0].id);
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
