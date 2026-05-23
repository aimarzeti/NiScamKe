function refreshPopupState() {
    const safePopup = document.getElementById("safe-popup");
    const dangerPopup = document.getElementById("danger-popup");

    chrome.storage.local.get(["lastScan", "scamStatus"], data => {
        const status = (data.lastScan?.status || data.scamStatus || "ALLOW").toUpperCase();
        const isBlocked = status === "BLOCK";

        safePopup.style.display = isBlocked ? "none" : "block";
        dangerPopup.style.display = isBlocked ? "block" : "none";
    });
}

function bindScanButton(buttonId) {
    const button = document.getElementById(buttonId);
    if (!button) {
        return;
    }

    button.addEventListener("click", () => {
        const originalText = button.textContent;
        button.textContent = "Scanning...";
        button.disabled = true;

        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs && tabs.length > 0) {
                chrome.tabs.reload(tabs[0].id);
            }

            setTimeout(() => {
                button.textContent = originalText;
                button.disabled = false;
                refreshPopupState();
            }, 1500);
        });
    });
}

document.addEventListener("DOMContentLoaded", () => {
    refreshPopupState();
    bindScanButton("safe-scan-btn");
    bindScanButton("danger-scan-btn");
});
