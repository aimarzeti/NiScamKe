document.addEventListener("DOMContentLoaded", function () {
    // ✅ FIX: Use getElementById to match the IDs in popup.html
    const safePopup = document.getElementById("safe-popup");
    const dangerPopup = document.getElementById("danger-popup");

    chrome.storage.local.get(["scamStatus", "scamType"], function (data) {
        if (data.scamStatus === "BLOCK") {
            safePopup.style.display = "none";
            dangerPopup.style.display = "block";
        } else {
            safePopup.style.display = "block";
            dangerPopup.style.display = "none";
        }
    });
});