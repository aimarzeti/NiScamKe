document.addEventListener("DOMContentLoaded", function () {

    const scanButton = document.getElementById("scan-btn");

    scanButton.addEventListener("click", function () {

        // UX feedback
        scanButton.textContent = "Scanning...";
        scanButton.disabled = true;

        // Reload current tab
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {

            chrome.tabs.reload(tabs[0].id);

            // Restore button after 1.5 seconds
            setTimeout(() => {
                scanButton.textContent = "Scan Again";
                scanButton.disabled = false;
            }, 1500);

        });

    });

});