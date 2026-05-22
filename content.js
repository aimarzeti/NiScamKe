/**
 * ScamShield AI - Layer 1: Client Browser Content Script
 * Responsibility: Monitor DOM viewport, grab current URL strings, and enforce blocking behavior.
 */

(function () {
    const currentURL = window.location.href;
    
    // Skip internal browser configurations, blank tabs, and development frames
    if (currentURL.startsWith("chrome://") || currentURL.startsWith("about:") || currentURL.startsWith("chrome-extension://")) return;

    console.log("[ScamShield AI] Scanning active URL payload:", currentURL);

    // Forward the URL string down the pipeline to background.js via internal Chrome runtime messaging
    chrome.runtime.sendMessage({ action: "CHECK_URL", url: currentURL }, (response) => {
        if (chrome.runtime.lastError) {
            console.warn("[ScamShield AI] Pipeline link warning: Backend service connection pending.");
            return;
        }

        // Check if the dual-protection system architecture issues a malicious verdict flag
        if (response && response.status === "SCAM") {
            console.error("[ScamShield AI] CRITICAL THREAT: Domain flagged as scam trap by Gemini AI infrastructure.");
            executeEnforcedBlock();
        } else {
            console.log("[ScamShield AI] Inspection pass: Domain clear for safe user operation.");
        }
    });

    /**
     * Replaces the entire malicious webpage window with a clean, raw HTML Warning Screen designed by Person 3
     */
    function executeEnforcedBlock() {
        // Overwrite document structures cleanly to halt any ongoing script compilation from the fake domain
        document.documentElement.innerHTML = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>🚨 ACCESS DENIED | ScamShield AI</title>
                <style>
                    body, html {
                        margin: 0; padding: 0; width: 100%; height: 100%;
                        background-color: #0d0d12; color: #ffffff;
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                        display: flex; align-items: center; justify-content: center;
                        overflow: hidden;
                    }
                    .alert-container {
                        max-width: 600px; text-align: center; padding: 45px;
                        border: 2px solid #ff3333; border-radius: 16px;
                        background: rgba(255, 51, 51, 0.03);
                        box-shadow: 0 25px 60px rgba(0,0,0,0.6);
                    }
                    .icon { font-size: 80px; margin-bottom: 20px; animation: warningPulse 2s infinite; }
                    h1 { font-size: 34px; font-weight: 700; margin: 0 0 15px 0; color: #ff4444; letter-spacing: -0.5px; }
                    p { font-size: 16px; color: #b4b4bf; line-height: 1.6; margin: 0 0 30px 0; }
                    .status-badge {
                        display: inline-block; padding: 6px 14px; background: #1c1c24;
                        color: #ff8888; font-size: 12px; font-family: monospace;
                        border-radius: 6px; border: 1px solid rgba(255,51,51,0.2); margin-bottom: 25px;
                    }
                    .btn-back {
                        display: inline-block; padding: 14px 36px; background: #ff3333;
                        color: #ffffff; font-weight: 600; text-decoration: none; border: none;
                        border-radius: 8px; transition: background 0.2s; cursor: pointer; font-size: 15px;
                    }
                    .btn-back:hover { background: #e02222; }
                    @keyframes warningPulse {
                        0% { transform: scale(1); }
                        50% { transform: scale(1.05); }
                        100% { transform: scale(1); }
                    }
                </style>
            </head>
            <body>
                <div class="alert-container">
                    <div class="icon">🚨</div>
                    <span class="status-badge">SECURITY STATUS: HIGH_RISK_PHISHING_BLOCKED</span>
                    <h1>Scam Website Intercepted</h1>
                    <p>ScamShield AI has restricted access to this page for your safety. Our intelligence engine has identified this domain as a malicious clone built to mimic Malaysian financial institutions and harvest your security credentials.</p>
                    <button class="btn-back" onclick="window.history.back();">Return to Safety</button>
                </div>
            </body>
            </html>
        `;
    }
})();