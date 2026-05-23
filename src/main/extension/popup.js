const API_BASE_URL = "http://localhost:8080";
const DEFAULT_LANGUAGE = "ms";

const UI_COPY = {
    ms: {
        languageLabel: "Bahasa",
        riskScoreLabel: "Skor risiko",
        statusLabel: "Status",
        confidenceTitle: "Keyakinan",
        modeTitle: "Mod",
        domainTitle: "Domain",
        whyLabel: "Sebab",
        privacyNote: "Nota privasi: Ni Scam Ke? tidak akan meminta kata laluan, OTP, atau maklumat perbankan.",
        scanButton: "Imbas Laman Ini",
        scanButtonLoading: "Sedang mengimbas laman...",
        waitingDecision: "Menunggu",
        currentTab: "Tab semasa",
        notScanned: "Belum diimbas",
        liveBackend: "Pelayan langsung",
        localFallback: "Semakan tempatan",
        reasonFallback: "Belum ada keputusan imbasan. Klik imbas untuk menyemak semula laman ini.",
        refreshingReason: "Memuat semula tab supaya pengimbas kandungan dapat menilai laman terkini.",
        states: {
            ALLOW: {
                title: "Bukan Scam!",
                subtitle: "Laman ini nampak selamat. Tetap berhati-hati sebelum memasukkan maklumat sensitif."
            },
            WARN: {
                title: "Berhati-hati",
                subtitle: "Ada tanda mencurigakan. Elakkan memasukkan kata laluan, OTP, atau butiran bayaran."
            },
            USER_BYPASS: {
                title: "Amaran dipintas",
                subtitle: "Anda memilih untuk teruskan atas risiko sendiri. Laman ini masih dianggap mencurigakan."
            },
            BLOCK: {
                title: "Laman berisiko tinggi",
                subtitle: "Kami menghentikan laman ini kerana ia menyerupai cubaan scam atau phishing."
            },
            WAITING: {
                title: "Sedia untuk imbas",
                subtitle: "Buka laman atau imbas tab semasa untuk melihat isyarat perlindungan terkini."
            },
            SCANNING: {
                title: "Sedang mengimbas",
                subtitle: "Ni Scam Ke? sedang menyemak laman semasa."
            }
        }
    },
    en: {
        languageLabel: "Language",
        riskScoreLabel: "Risk score",
        statusLabel: "Status",
        confidenceTitle: "Confidence",
        modeTitle: "Mode",
        domainTitle: "Domain",
        whyLabel: "Why",
        privacyNote: "Privacy note: Ni Scam Ke? never asks for passwords, OTPs, or banking credentials.",
        scanButton: "Scan Current Page",
        scanButtonLoading: "Scanning current tab...",
        waitingDecision: "Waiting",
        currentTab: "Current tab",
        notScanned: "Not scanned",
        liveBackend: "Live backend",
        localFallback: "Local fallback",
        reasonFallback: "No scan result yet. Click scan to refresh the current page.",
        refreshingReason: "Refreshing the tab so the content scanner can evaluate the latest page.",
        states: {
            ALLOW: {
                title: "Looks safe",
                subtitle: "This page looks safe. Keep an eye out before entering sensitive details."
            },
            WARN: {
                title: "Use caution",
                subtitle: "Suspicious signs were found. Avoid entering passwords, OTPs, or payment details."
            },
            USER_BYPASS: {
                title: "Bypassed warning",
                subtitle: "You continued at your own risk. This page is still considered suspicious."
            },
            BLOCK: {
                title: "High-risk page",
                subtitle: "We stopped this page because it looks like a scam or phishing attempt."
            },
            WAITING: {
                title: "Ready to scan",
                subtitle: "Open a page or scan the current tab to see the latest protection signal."
            },
            SCANNING: {
                title: "Scanning now",
                subtitle: "Checking the current page with Ni Scam Ke? protection."
            }
        }
    }
};

const LOCAL_REASON_TRANSLATIONS = {
    ms: {
        "You chose to continue anyway. This page is still considered risky.": "Anda memilih untuk teruskan. Laman ini masih dianggap berisiko.",
        "Temporary user bypass is active for this page.": "Pintasan sementara pengguna sedang aktif untuk laman ini.",
        "No significant phishing indicators detected.": "Tiada petunjuk phishing yang ketara dikesan.",
        "Some scam-like signals were found, but not enough to hard-block.": "Beberapa tanda seperti scam ditemui, tetapi belum cukup untuk sekatan penuh.",
        "This looks like a free-aid or free-device application scam.": "Ini kelihatan seperti scam permohonan bantuan atau peranti percuma.",
        "The page combines typo-filled application text with Telegram or personal-detail collection.": "Laman ini menggabungkan teks permohonan yang banyak kesilapan dengan kutipan Telegram atau maklumat peribadi.",
        "Protection status is uncertain. Avoid entering passwords or OTPs here.": "Status perlindungan tidak pasti. Elakkan memasukkan kata laluan atau OTP di sini."
    },
    en: {}
};

const translationCache = new Map();
let renderSequence = 0;

function formatPercent(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
        return "--";
    }

    return `${Math.round(numeric * 100)}%`;
}

function getCopy(language) {
    return UI_COPY[language] || UI_COPY[DEFAULT_LANGUAGE];
}

function formatMode(scan, copy) {
    if (!scan) {
        return copy.notScanned;
    }

    if (scan.backendAvailable === false) {
        return copy.localFallback;
    }

    return scan.scanMode === "LIVE_BACKEND" ? copy.liveBackend : scan.scanMode || copy.liveBackend;
}

function setCardState(status) {
    const card = document.querySelector(".hero-card");
    card.classList.remove("state-allow", "state-warn", "state-block");

    if (status === "ALLOW") {
        card.classList.add("state-allow");
    } else if (status === "WARN" || status === "USER_BYPASS") {
        card.classList.add("state-warn");
    } else if (status === "BLOCK") {
        card.classList.add("state-block");
    }
}

function translateReasonLocally(text, language) {
    return LOCAL_REASON_TRANSLATIONS[language]?.[text] || text;
}

async function translateWithAi(text, language) {
    if (!text || language === "en") {
        return text;
    }

    const localTranslation = translateReasonLocally(text, language);
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

async function renderPopup(scan, language = DEFAULT_LANGUAGE) {
    const currentRender = ++renderSequence;
    const ui = getCopy(language);
    const status = (scan?.status || "WAITING").toUpperCase();
    const displayStatus = scan?.scanMode === "USER_BYPASS" ? "USER_BYPASS" : status;
    const copy = ui.states[displayStatus] || ui.states.WAITING;
    const riskScore = Number.isFinite(Number(scan?.riskScore)) ? Number(scan.riskScore) : 0;
    const rawReason = scan?.reason || ui.reasonFallback;
    const reason = displayStatus === "SCANNING"
        ? rawReason
        : await translateWithAi(rawReason, language);

    if (currentRender !== renderSequence) {
        return;
    }

    setCardState(displayStatus);

    document.getElementById("languageLabel").textContent = ui.languageLabel;
    document.getElementById("riskScoreLabel").textContent = ui.riskScoreLabel;
    document.getElementById("statusLabel").textContent = ui.statusLabel;
    document.getElementById("confidenceTitle").textContent = ui.confidenceTitle;
    document.getElementById("modeTitle").textContent = ui.modeTitle;
    document.getElementById("domainTitle").textContent = ui.domainTitle;
    document.getElementById("whyLabel").textContent = ui.whyLabel;
    document.getElementById("privacyNote").textContent = ui.privacyNote;
    const scanButton = document.getElementById("scanButton");
    if (!scanButton.disabled) {
        scanButton.textContent = ui.scanButton;
    }
    document.getElementById("statusTitle").textContent = copy.title;
    document.getElementById("statusSubtitle").textContent = copy.subtitle;
    document.getElementById("riskScore").textContent = scan ? `${Math.round(riskScore)}/100` : "--/100";
    document.getElementById("riskFill").style.width = scan ? `${Math.max(0, Math.min(100, riskScore))}%` : "0%";
    document.getElementById("decisionLabel").textContent = scan ? displayStatus : ui.waitingDecision;
    document.getElementById("confidenceLabel").textContent = formatPercent(scan?.confidence);
    document.getElementById("modeLabel").textContent = formatMode(scan, ui);
    document.getElementById("domainLabel").textContent = scan?.domain || ui.currentTab;
    document.getElementById("reasonText").textContent = reason;
}

function refreshPopupState() {
    chrome.storage.local.get(["lastScan", "uiLanguage"], data => {
        const language = data.uiLanguage || DEFAULT_LANGUAGE;
        document.getElementById("languageSelect").value = language;
        renderPopup(data.lastScan, language);
    });
}

function bindScanButton() {
    const button = document.getElementById("scanButton");

    button.addEventListener("click", () => {
        const language = document.getElementById("languageSelect").value || DEFAULT_LANGUAGE;
        const ui = getCopy(language);
        const originalText = button.textContent;
        button.textContent = ui.scanButtonLoading;
        button.disabled = true;
        renderPopup({
            status: "SCANNING",
            riskScore: 50,
            confidence: 0.5,
            domain: language === "ms" ? "Memuat semula" : "Refreshing",
            reason: ui.refreshingReason,
            scanMode: "SCANNING",
            backendAvailable: true
        }, language);
        button.textContent = ui.scanButtonLoading;

        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs && tabs.length > 0 && tabs[0].id) {
                chrome.tabs.reload(tabs[0].id);
            }

            [900, 1800, 3200].forEach(delay => {
                setTimeout(refreshPopupState, delay);
            });

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

    document.getElementById("languageSelect").addEventListener("change", event => {
        const language = event.target.value || DEFAULT_LANGUAGE;
        chrome.storage.local.set({ uiLanguage: language }, refreshPopupState);
    });
});
