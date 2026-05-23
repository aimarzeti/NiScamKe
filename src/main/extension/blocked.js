const API_BASE_URL = "http://localhost:8080";

function decodeReasons(rawReasons, fallbackReason) {
    if (!rawReasons) {
        return fallbackReason ? [fallbackReason] : ["Gemini AI flagged suspicious scam signals."];
    }

    try {
        const parsed = JSON.parse(rawReasons);
        if (Array.isArray(parsed) && parsed.length > 0) {
            return parsed.map(item => String(item));
        }
    } catch (error) {
        return [rawReasons];
    }

    return fallbackReason ? [fallbackReason] : ["Gemini AI flagged suspicious scam signals."];
}

function formatPercent(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
        return "-";
    }

    return `${Math.round(numeric * 100)}%`;
}

async function readErrorMessage(response) {
    try {
        const data = await response.json();
        return data.message || data.error || `Request failed with status ${response.status}.`;
    } catch (error) {
        return `Request failed with status ${response.status}.`;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(window.location.search);
    const originalUrl = params.get("blocked") || "";
    const reason = params.get("reason") || "Gemini AI flagged suspicious scam signals.";
    const decisionId = params.get("decisionId") || "Not available";
    const evidenceSources = params.get("sources") || "AI_MODEL";
    const riskScore = Number(params.get("riskScore"));
    const confidence = params.get("confidence");
    const reasons = decodeReasons(params.get("reasons"), reason);

    const blockedUrlEl = document.getElementById("blockedUrl");
    const decisionIdEl = document.getElementById("decisionId");
    const riskScoreEl = document.getElementById("riskScore");
    const confidenceEl = document.getElementById("confidence");
    const reasonsListEl = document.getElementById("reasonsList");
    const riskFillEl = document.getElementById("riskFill");
    const riskPillEl = document.getElementById("riskPill");
    const sourceLineEl = document.getElementById("sourceLine");
    const goBackButton = document.getElementById("goBackButton");
    const continueButton = document.getElementById("continueButton");

    const safeRiskScore = Number.isFinite(riskScore) ? Math.max(0, Math.min(100, riskScore)) : 85;

    blockedUrlEl.textContent = originalUrl || "Unknown URL";
    decisionIdEl.textContent = decisionId;
    riskScoreEl.textContent = `${safeRiskScore}/100`;
    confidenceEl.textContent = formatPercent(confidence);
    riskFillEl.style.width = `${safeRiskScore}%`;
    riskPillEl.textContent = safeRiskScore >= 80 ? "This is a scam!" : safeRiskScore >= 50 ? "Suspicious page" : "Low risk";
    sourceLineEl.textContent = `Evidence source: ${formatEvidenceSources(evidenceSources)}`;

    reasonsListEl.innerHTML = "";
    reasons.forEach(text => {
        const item = document.createElement("li");
        item.textContent = text;
        reasonsListEl.appendChild(item);
    });

    goBackButton.addEventListener("click", () => {
        if (history.length > 1) {
            history.back();
        } else {
            window.location.href = "https://www.google.com";
        }
    });

    let continueCompleted = false;

    function continueToOriginalUrl() {
        if (continueCompleted) {
            return;
        }

        continueCompleted = true;
        continueButton.textContent = "Opening at your own risk...";
        continueButton.disabled = true;

        if (!originalUrl) {
            history.back();
            return;
        }

        chrome.storage.local.set({
            temporaryBypass: {
                url: originalUrl,
                expiresAt: Date.now() + 60000,
                riskScore: safeRiskScore,
                confidence: Number(confidence) || 0.72,
                decisionId: decisionId === "Not available" ? null : decisionId,
                reason
            }
        }, () => {
            window.location.href = originalUrl;
        });
    }

    continueButton.addEventListener("click", event => {
        event.preventDefault();
        continueToOriginalUrl();
    });

    const falsePositiveForm = document.getElementById("falsePositiveForm");
    const reportButton = document.getElementById("reportButton");
    const reportStatus = document.getElementById("reportStatus");

    falsePositiveForm.addEventListener("submit", async event => {
        event.preventDefault();

        const reporterEmail = document.getElementById("reporterEmail").value.trim();
        const reportReason = document.getElementById("reportReason").value.trim() || "User believes this site is legitimate.";

        reportButton.disabled = true;
        reportButton.textContent = "Submitting...";
        reportStatus.textContent = "";

        try {
            const response = await fetch(`${API_BASE_URL}/api/v1/false-positive`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: originalUrl,
                    decisionId: decisionId === "Not available" ? null : decisionId,
                    reporterEmail: reporterEmail || null,
                    reason: reportReason
                })
            });

            if (!response.ok) {
                throw new Error(await readErrorMessage(response));
            }

            const data = await response.json();
            reportStatus.textContent = data.message || "Thanks. Your review request was submitted.";
            falsePositiveForm.reset();
        } catch (error) {
            reportStatus.textContent = `Could not submit review right now. ${error.message}`;
        } finally {
            reportButton.disabled = false;
            reportButton.textContent = "Submit review request";
        }
    });
});
