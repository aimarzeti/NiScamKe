document.addEventListener("DOMContentLoaded", function () {
    const goBackButton = document.querySelector(".primary-btn");
    const continueButton = document.querySelector(".secondary-btn");

    goBackButton.addEventListener("click", function () {
        window.location.href = "https://www.google.com";
    });

    continueButton.addEventListener("click", function () {
        alert("Proceeding to the potentially harmful site is not recommended. Please consider going back to safety.");
    }); 
});
