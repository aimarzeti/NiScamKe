document.addEventListener("DOMContentLoaded", function () {
    const safePopup = document.querySelector(".safe-popup");
    const dangerPopup = document.querySelector(".danger-popup");

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