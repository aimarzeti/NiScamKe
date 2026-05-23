function formatTime(isoTimestamp) {
    if (!isoTimestamp) {
        return "-";
    }

    const date = new Date(isoTimestamp);
    if (Number.isNaN(date.getTime())) {
        return isoTimestamp;
    }

    return date.toLocaleString();
}

function formatConfidence(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
        return "-";
    }

    return `${Math.round(numeric * 100)}%`;
}

function renderLastScan(scan) {
    const root = document.getElementById("popupRoot");
    const statusLine = document.getElementById("statusLine");
    const riskTag = document.getElementById("riskTag");

    const urlLine = document.getElementById("urlLine");
    const reasonLine = document.getElementById("reasonLine");
    const riskLine = document.getElementById("riskLine");
    const confidenceLine = document.getElementById("confidenceLine");
    const timeLine = document.getElementById("timeLine");

    if (!scan) {
        root.className = "popup";
        riskTag.textContent = "Ready to scan";
        statusLine.textContent = "No scan result yet.";
        urlLine.textContent = "-";
        reasonLine.textContent = "-";
        riskLine.textContent = "-";
        confidenceLine.textContent = "-";
        timeLine.textContent = "-";
        return;
    }

    const status = (scan.status || "ALLOW").toUpperCase();
    root.className = `popup ${status === "BLOCK" ? "block" : status === "WARN" ? "warn" : "safe"}`;

    riskTag.textContent = status === "BLOCK" ? "Blocked" : status === "WARN" ? "Warning" : "Safe";
    statusLine.textContent = status === "BLOCK"
        ? "Potential scam blocked on this tab."
        : status === "WARN"
            ? "Caution: suspicious signals detected."
            : "No major scam signal detected.";

    urlLine.textContent = scan.scannedUrl || "-";
    reasonLine.textContent = scan.reason || "No reason provided.";
    riskLine.textContent = Number.isFinite(Number(scan.riskScore))
        ? `${scan.riskScore}/100`
        : "-";
    confidenceLine.textContent = formatConfidence(scan.confidence);
    timeLine.textContent = formatTime(scan.scannedAt);
}

function sendDemoNotification(status) {
    chrome.runtime.sendMessage({ action: "triggerDemoNotification", status }, () => {
        chrome.storage.local.get(["lastScan"], ({ lastScan }) => {
            renderLastScan(lastScan);
        });
    });
}

document.addEventListener("DOMContentLoaded", () => {
    const scanButton = document.getElementById("scanBtn");
    const demoBlockButton = document.getElementById("demoBlockBtn");
    const demoSafeButton = document.getElementById("demoSafeBtn");

    chrome.storage.local.get(["lastScan"], ({ lastScan }) => {
        renderLastScan(lastScan);
    });

    scanButton.addEventListener("click", () => {
        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";

        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs && tabs.length > 0) {
                chrome.tabs.reload(tabs[0].id);
            }

            setTimeout(() => {
                scanButton.textContent = "Scan Current Tab";
                scanButton.disabled = false;
                chrome.storage.local.get(["lastScan"], ({ lastScan }) => {
                    renderLastScan(lastScan);
                });
            }, 1600);
        });
    });

    demoBlockButton.addEventListener("click", () => {
        sendDemoNotification("BLOCK");
    });

    demoSafeButton.addEventListener("click", () => {
        sendDemoNotification("ALLOW");
    });
});
