/**
 * ScamShield AI - Background Service Worker Network Broker
 * Responsibility: Route URL checking requests from extension views to Person 1's Spring Boot backend.
 */

// Production API endpoint hosted on Render by Person 1 (Switch to localhost during staging sessions)
const BACKEND_API_URL = "https://scamshield.onrender.com/api/check-domain";

// Fallback Sandbox Registry: Guarantees your live demo never fails even during server network blackouts
const LOCAL_DEMO_REGISTRY = [
    "maybank-security",
    "cimb-clicks-verification",
    "bankislam-rewards-login",
    "shopee-lucky-draw",
    "whatsapp-gift-free"
];

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "CHECK_URL") {
        const structuralURL = request.url.toLowerCase();

        // Pass 1: Local database cache screening (Simulating fast-path detection engine)
        const matchLocalDatabaseFlag = LOCAL_DEMO_REGISTRY.some(keyword => structuralURL.includes(keyword));
        
        if (matchLocalDatabaseFlag) {
            console.warn("[ScamShield AI Background] Match found in Local Cache Registry. Emitting block sequence.");
            sendResponse({ status: "SCAM", source: "local_cache_registry" });
            return false; 
        }

        // Pass 2: Fire standard HTTP POST data stream upstream to Person 1's Spring Boot server on Render
        fetch(BACKEND_API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url })
        })
        .then(res => {
            if (!res.ok) throw new Error("Cloud network node connection fault.");
            return res.json();
        })
        .then(data => {
            // Evaluates structured backend verdict payload return structures: {"status": "SCAM"} or {"status": "SAFE"}
            sendResponse({ status: data.status, source: "gemini_ai_cloud" });
        })
        .catch(err => {            
            console.error("[ScamShield AI Background] Cloud transmission exception:", err.message);
            // Safe failover state parameters to avoid blocking genuine everyday websites if backend disconnects
            sendResponse({ status: "SAFE", source: "failover_bypass" });
        });

        return true; // Keeps the channel open for async fetch
    }
});