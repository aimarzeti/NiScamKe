document.addEventListener("DOMContentLoaded", function () {
    const goBackButton = document.querySelector(".primary-btn");
    const continueButton = document.querySelector(".secondary-btn");

    // ✅ FIX: Read the original blocked URL from the query string
    const params = new URLSearchParams(window.location.search);
    const originalUrl = params.get("blocked");

    goBackButton.addEventListener("click", function () {
        // Go back to previous page, or Google if no history
        if (history.length > 1) {
            history.back();
        } else {
            window.location.href = "https://www.google.com";
        }
    });

    continueButton.addEventListener("click", function () {
        // ✅ FIX: Navigate to the original site instead of just alerting
        if (originalUrl) {
            window.location.href = originalUrl;
        } else {
            history.back();
        }
    });
});