const STATE_COPY = {
    ALLOW: {
        title: "Looks safe",
        subtitle: "Laman ini nampak selamat. Keep an eye out before entering sensitive details."
    },
    WARN: {
        title: "Use caution",
        subtitle: "Ada tanda mencurigakan. Avoid entering passwords, OTPs, or payment details."
    },
    BLOCK: {
        title: "High-risk page",
        subtitle: "Kami berhentikan laman ini kerana ia menyerupai cubaan scam atau phishing."
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
    } else if (status === "WARN") {
        card.classList.add("state-warn");
    } else if (status === "BLOCK") {
        card.classList.add("state-block");
    }
}

function renderPopup(scan) {
    const status = (scan?.status || "WAITING").toUpperCase();
    const copy = STATE_COPY[status] || STATE_COPY.WAITING;
    const riskScore = Number.isFinite(Number(scan?.riskScore)) ? Number(scan.riskScore) : 0;
    const reason = scan?.reason || "No scan result yet. Click scan to refresh the current page.";

    setCardState(status);

    document.getElementById("statusTitle").textContent = copy.title;
    document.getElementById("statusSubtitle").textContent = copy.subtitle;
    document.getElementById("riskScore").textContent = scan ? `${Math.round(riskScore)}/100` : "--/100";
    document.getElementById("riskFill").style.width = scan ? `${Math.max(0, Math.min(100, riskScore))}%` : "0%";
    document.getElementById("decisionLabel").textContent = scan ? status : "Waiting";
    document.getElementById("confidenceLabel").textContent = formatPercent(scan?.confidence);
    document.getElementById("modeLabel").textContent = formatMode(scan);
    document.getElementById("domainLabel").textContent = scan?.domain || "Current tab";
    document.getElementById("reasonText").textContent = reason;
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

        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs && tabs.length > 0 && tabs[0].id) {
                chrome.tabs.reload(tabs[0].id);
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
