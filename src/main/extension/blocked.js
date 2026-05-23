const API_BASE_URL = "http://localhost:8080";
const DEFAULT_LANGUAGE = "ms";

const UI_COPY = {
    ms: {
        languageLabel: "Bahasa",
        pageTitle: "Potensi scam disekat",
        blockedUrlLabel: "URL disekat",
        decisionIdLabel: "ID keputusan",
        riskScoreLabel: "Skor risiko",
        confidenceLabel: "Keyakinan",
        whyTitle: "Sebab laman ini ditanda",
        privacyNote: "Ni Scam Ke? tidak akan meminta kata laluan, OTP, PIN, atau butiran kad penuh. Jika anda teruskan, anda menerima risiko sendiri.",
        goBackButton: "Kembali selamat",
        continueButton: "Teruskan juga",
        openingRisk: "Membuka atas risiko sendiri...",
        falsePositiveSummary: "Keputusan ini salah? Laporkan false positive",
        emailLabel: "E-mel (pilihan)",
        reportReasonLabel: "Mengapa laman ini mungkin selamat",
        reportPlaceholder: "Contoh: Ini domain rasmi organisasi saya.",
        reportButton: "Hantar semakan",
        submitting: "Sedang menghantar...",
        defaultReportReason: "Pengguna percaya laman ini sah.",
        submitted: "Terima kasih. Permintaan semakan anda telah dihantar.",
        submitFailed: "Tidak dapat menghantar semakan sekarang. Sila cuba lagi apabila backend aktif.",
        evidenceSource: "Sumber bukti",
        unknownUrl: "URL tidak diketahui",
        riskLabels: {
            high: "Risiko tinggi",
            medium: "Risiko sederhana",
            low: "Risiko rendah"
        }
    },
    en: {
        languageLabel: "Language",
        pageTitle: "Potential scam blocked",
        blockedUrlLabel: "Blocked URL",
        decisionIdLabel: "Decision ID",
        riskScoreLabel: "Risk score",
        confidenceLabel: "Confidence",
        whyTitle: "Why this was flagged",
        privacyNote: "Ni Scam Ke? will never ask for your password, OTP, PIN, or full card details. If you continue, you accept the risk yourself.",
        goBackButton: "Go to safety",
        continueButton: "Continue anyway",
        openingRisk: "Opening at your own risk...",
        falsePositiveSummary: "This looks wrong? Report false positive",
        emailLabel: "Email (optional)",
        reportReasonLabel: "Why this is likely safe",
        reportPlaceholder: "For example: This is my official company login domain.",
        reportButton: "Submit review request",
        submitting: "Submitting...",
        defaultReportReason: "User believes this site is legitimate.",
        submitted: "Thanks. Your review request was submitted.",
        submitFailed: "Could not submit review right now. Please try again when backend is online.",
        evidenceSource: "Evidence source",
        unknownUrl: "Unknown URL",
        riskLabels: {
            high: "High Risk",
            medium: "Medium Risk",
            low: "Low Risk"
        }
    }
};

const LOCAL_TRANSLATIONS = {
    ms: {
        "Potential phishing behavior detected.": "Tingkah laku phishing berpotensi dikesan.",
        "Suspicious signals detected by the scan engine.": "Isyarat mencurigakan dikesan oleh enjin imbasan.",
        "This looks like a free-aid or free-device application scam.": "Ini kelihatan seperti scam permohonan bantuan atau peranti percuma.",
        "The page combines typo-filled application text with Telegram or personal-detail collection.": "Laman ini menggabungkan teks permohonan yang banyak kesilapan dengan kutipan Telegram atau maklumat peribadi.",
        "This page offers free aid or devices while collecting contact details on an untrusted domain.": "Laman ini menawarkan bantuan atau peranti percuma sambil mengutip maklumat hubungan pada domain tidak dipercayai.",
        "Telegram-based application flows are a common scam pattern.": "Aliran permohonan melalui Telegram ialah corak scam yang biasa.",
        "AI phishing analysis flagged suspicious signals.": "Analisis AI phishing menanda isyarat mencurigakan."
    },
    en: {}
};

const translationCache = new Map();
let languageRenderSequence = 0;

function getCopy(language) {
    return UI_COPY[language] || UI_COPY[DEFAULT_LANGUAGE];
}

function translateLocally(text, language) {
    return LOCAL_TRANSLATIONS[language]?.[text] || text;
}

async function translateWithAi(text, language) {
    if (!text || language === "en") {
        return text;
    }

    const localTranslation = translateLocally(text, language);
    if (localTranslation !== text) {
        return localTranslation;
    }

    const cacheKey = `${language}:${text}`;
    if (translationCache.has(cacheKey)) {
        return translationCache.get(cacheKey);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 600);

    try {
        const response = await fetch(`${API_BASE_URL}/api/v1/translate-ui`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text, targetLanguage: language }),
            signal: controller.signal
        });

        if (!response.ok) {
            return text;
        }

        const data = await response.json();
        const translated = data.translatedText || text;
        translationCache.set(cacheKey, translated);
        return translated;
    } catch (error) {
        return text;
    } finally {
        clearTimeout(timeoutId);
    }
}

function decodeReasons(rawReasons, fallbackReason) {
    if (!rawReasons) {
        return fallbackReason ? [fallbackReason] : ["Suspicious signals detected by the scan engine."];
    }

    try {
        const parsed = JSON.parse(rawReasons);
        if (Array.isArray(parsed) && parsed.length > 0) {
            return parsed.map(item => String(item));
        }
    } catch (error) {
        return [rawReasons];
    }

    return fallbackReason ? [fallbackReason] : ["Suspicious signals detected by the scan engine."];
}

function formatPercent(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
        return "-";
    }

    return `${Math.round(numeric * 100)}%`;
}

document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(window.location.search);
    const originalUrl = params.get("blocked") || "";
    const reason = params.get("reason") || "Potential phishing behavior detected.";
    const decisionId = params.get("decisionId") || "Not available";
    const evidenceSources = params.get("sources") || "RULE_ENGINE";
    const riskScore = Number(params.get("riskScore"));
    const confidence = params.get("confidence");
    const reasons = decodeReasons(params.get("reasons"), reason);

    const blockedUrlEl = document.getElementById("blockedUrl");
    const decisionIdEl = document.getElementById("decisionId");
    const riskScoreEl = document.getElementById("riskScore");
    const confidenceEl = document.getElementById("confidence");
    const summaryLineEl = document.getElementById("summaryLine");
    const reasonsListEl = document.getElementById("reasonsList");
    const riskFillEl = document.getElementById("riskFill");
    const riskPillEl = document.getElementById("riskPill");
    const sourceLineEl = document.getElementById("sourceLine");

    decisionIdEl.textContent = decisionId;

    const safeRiskScore = Number.isFinite(riskScore) ? Math.max(0, Math.min(100, riskScore)) : 85;
    riskScoreEl.textContent = `${safeRiskScore}/100`;
    confidenceEl.textContent = formatPercent(confidence);
    riskFillEl.style.width = `${safeRiskScore}%`;
    async function applyLanguage(language) {
        const currentRender = ++languageRenderSequence;
        const ui = getCopy(language);
        document.documentElement.lang = language === "en" ? "en" : "ms";
        document.getElementById("languageSelect").value = language;
        document.getElementById("languageLabel").textContent = ui.languageLabel;
        document.getElementById("pageTitle").textContent = ui.pageTitle;
        document.getElementById("blockedUrlLabel").textContent = ui.blockedUrlLabel;
        document.getElementById("decisionIdLabel").textContent = ui.decisionIdLabel;
        document.getElementById("riskScoreLabel").textContent = ui.riskScoreLabel;
        document.getElementById("confidenceLabel").textContent = ui.confidenceLabel;
        document.getElementById("whyTitle").textContent = ui.whyTitle;
        document.getElementById("privacyNote").textContent = ui.privacyNote;
        document.getElementById("goBackButton").textContent = ui.goBackButton;
        document.getElementById("continueButton").textContent = ui.continueButton;
        document.getElementById("falsePositiveSummary").textContent = ui.falsePositiveSummary;
        document.getElementById("emailLabel").textContent = ui.emailLabel;
        document.getElementById("reportReasonLabel").textContent = ui.reportReasonLabel;
        document.getElementById("reportReason").placeholder = ui.reportPlaceholder;
        document.getElementById("reportButton").textContent = ui.reportButton;
        blockedUrlEl.textContent = originalUrl || ui.unknownUrl;
        const translatedSummary = await translateWithAi(reason, language);
        const translatedReasons = await Promise.all(reasons.map(text => translateWithAi(text, language)));

        if (currentRender !== languageRenderSequence) {
            return;
        }

        summaryLineEl.textContent = translatedSummary;
        sourceLineEl.textContent = `${ui.evidenceSource}: ${evidenceSources}`;

        riskPillEl.textContent = safeRiskScore >= 80
            ? ui.riskLabels.high
            : safeRiskScore >= 50
                ? ui.riskLabels.medium
                : ui.riskLabels.low;

        reasonsListEl.innerHTML = "";
        for (const text of translatedReasons) {
            const item = document.createElement("li");
            item.textContent = text;
            reasonsListEl.appendChild(item);
        }
    }

    chrome.storage.local.get(["uiLanguage"], data => {
        applyLanguage(data.uiLanguage || DEFAULT_LANGUAGE);
    });

    document.getElementById("languageSelect").addEventListener("change", event => {
        const language = event.target.value || DEFAULT_LANGUAGE;
        chrome.storage.local.set({ uiLanguage: language }, () => applyLanguage(language));
    });

    const goBackButton = document.getElementById("goBackButton");
    const continueButton = document.getElementById("continueButton");

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
        const selectedLanguage = document.getElementById("languageSelect").value || DEFAULT_LANGUAGE;
        continueButton.textContent = getCopy(selectedLanguage).openingRisk;
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
        const selectedLanguage = document.getElementById("languageSelect").value || DEFAULT_LANGUAGE;
        const ui = getCopy(selectedLanguage);
        const reportReason = document.getElementById("reportReason").value.trim() || ui.defaultReportReason;

        reportButton.disabled = true;
        reportButton.textContent = ui.submitting;
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
                throw new Error(`Request failed with status ${response.status}`);
            }

            const data = await response.json();
            reportStatus.textContent = selectedLanguage === "ms" ? ui.submitted : data.message || ui.submitted;
            falsePositiveForm.reset();
        } catch (error) {
            reportStatus.textContent = ui.submitFailed;
        } finally {
            reportButton.disabled = false;
            reportButton.textContent = ui.reportButton;
        }
    });
});
