package com.niscamke.backend.service;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.niscamke.backend.service.UrlFeatureExtractorService.UrlRiskAssessment;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class GeminiIntegrationService {

    private static final String GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s";

    @Value("${gemini.api.key:}")
    private String apiKey;

    @Value("${gemini.api.model:gemini-2.0-flash}")
    private String model;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public GeminiIntegrationService() {
        this(createRestTemplate(), new ObjectMapper());
    }

    GeminiIntegrationService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public record GeminiAnalysis(boolean scam, List<String> reasons) {
    }

    public boolean analyzeWithGemini(String domain, String pageText) {
        String normalizedDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);

        int structuralRisk = calculateStructuralRisk(normalizedDomain, pageText);
        if (structuralRisk >= 40) {
            System.out.println("[ScamShield Fast-Path] Structural bank mimic detected. Hard-blocking threat.");
            return true;
        }

        // 2. Fallback to Live AI Analysis (Google Gemini API call)
        if (apiKey == null || apiKey.isBlank()) {
            System.err.println("[ScamShield Warning] Missing Gemini API key parameter config.");
            return false;
        }

        try {
            String targetUrlEndpoint = GEMINI_API_URL + apiKey;

            // Enhanced system instruction: stronger prompt for consistent phishing detection
            String systemInstructionPrompt = 
                "You are a cybersecurity expert specializing in phishing and scam detection. " +
                "Analyze the following domain and page content for signs of phishing, impersonation, or scam. " +
                "Consider: domain spoofing (similar to legitimate banks), typosquatting, misspelled brand names, typo-filled credential requests, fake login forms, suspicious URLs, urgency tactics, requests for credentials, free-aid or free-device bait, Telegram/WhatsApp contact collection, and application pages with obvious typos such as aplly. " +
                "If the domain or page text appears to imitate a bank with small spelling changes, or offers free aid/devices while collecting contact details through typo-filled forms, mark it as SCAM. " +
                "Respond with ONLY a single word: SCAM or SAFE. No punctuation, no explanation, no extra text.";

            String analyticalPayload = String.format(
                "Domain: %s\nPage Text: %s",
                normalizedDomain,
                (pageText != null && pageText.length() > 800) ? pageText.substring(0, 800) : pageText
            );

            // ✅ Proper Gemini request structure
            Map<String, Object> requestBodyMap = new HashMap<>();

            // System instruction as separate field
            Map<String, Object> systemInstruction = new HashMap<>();
            systemInstruction.put("parts", Collections.singletonList(
                Map.of("text", systemInstructionPrompt)
            ));
            requestBodyMap.put("systemInstruction", systemInstruction);

            // User content
            Map<String, Object> userContent = Map.of(
                "role", "user",
                "parts", Collections.singletonList(Map.of("text", analyticalPayload))
            );
            requestBodyMap.put("contents", Collections.singletonList(userContent));

            // Force deterministic output: low temperature for consistency, small max tokens
            requestBodyMap.put("generationConfig", Map.of(
                "temperature", 0.0,
                "maxOutputTokens", 10
            ));

            // Set content headers
            HttpHeaders standardHeaders = new HttpHeaders();
            standardHeaders.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> outboundHttpRequestEntity = new HttpEntity<>(requestBodyMap, standardHeaders);

            // Send live POST request to Google Cloud
            ResponseEntity<String> externalServiceApiResponse = restTemplate.postForEntity(targetUrlEndpoint, outboundHttpRequestEntity, String.class);

            // Parse response body if request is successful (HTTP 200)
            if (externalServiceApiResponse.getStatusCode() == HttpStatus.OK && externalServiceApiResponse.getBody() != null) {
                return parseGeminiResponse(externalServiceApiResponse.getBody());
            } else {
                System.err.println("[ScamShield] Unexpected HTTP status: " + externalServiceApiResponse.getStatusCode());
            }

        } catch (RestClientException e) {
            System.err.println("[ScamShield System Fault] Gemini API Connection Error: " + e.getMessage());
        }

        return false;
    }

    /**
     * Robust Gemini response parser with edge case handling.
     * Handles missing nodes, null values, extra whitespace, and punctuation.
     */
    private boolean parseGeminiResponse(String responseBody) {
        try {
            JsonNode parsedRootNode = objectMapper.readTree(responseBody);

            // Edge case 1: Missing candidates array
            if (!parsedRootNode.has("candidates") || parsedRootNode.get("candidates").isEmpty()) {
                System.err.println("[ScamShield Parser] No candidates in Gemini response");
                return false;
            }

            JsonNode candidatesArray = parsedRootNode.get("candidates");

            // Edge case 2: First candidate missing or null
            if (candidatesArray.get(0) == null) {
                System.err.println("[ScamShield Parser] First candidate is null");
                return false;
            }

            JsonNode firstCandidate = candidatesArray.get(0);

            // Edge case 3: Missing content field
            if (!firstCandidate.has("content") || firstCandidate.get("content") == null) {
                System.err.println("[ScamShield Parser] Content field missing");
                return false;
            }

            JsonNode content = firstCandidate.get("content");

            // Edge case 4: Missing parts array
            if (!content.has("parts") || content.get("parts").isEmpty()) {
                System.err.println("[ScamShield Parser] Parts array missing or empty");
                return false;
            }

            JsonNode partsArray = content.get("parts");

            // Edge case 5: First part missing or null
            if (partsArray.get(0) == null) {
                System.err.println("[ScamShield Parser] First part is null");
                return false;
            }

            JsonNode firstPart = partsArray.get(0);

            // Edge case 6: Missing text field
            if (!firstPart.has("text") || firstPart.get("text").isNull()) {
                System.err.println("[ScamShield Parser] Text field missing or null");
                return false;
            }

            // Extract and normalize response text
            String rawOutput = firstPart.get("text").asText()
                .trim()
                .toUpperCase(Locale.ROOT)
                .replaceAll("[^A-Z]", ""); // Remove punctuation and whitespace

            System.out.println("[ScamShield Engine] Gemini response (cleaned): " + rawOutput);

            // Edge case 7: Unexpected response format
            if (rawOutput.isEmpty()) {
                System.err.println("[ScamShield Parser] Response text is empty after cleaning");
                return false;
            }

            return "SCAM".equals(rawOutput);

        } catch (IOException e) {
            System.err.println("[ScamShield Parser] Error parsing Gemini response: " + e.getMessage());
            return false;
        }
    }

    private GeminiAnalysis parseGeminiAnalysisResponse(String responseBody, int structuralRisk) {
        try {
            String rawOutput = extractGeminiText(responseBody);
            if (rawOutput.isBlank()) {
                return new GeminiAnalysis(structuralRisk >= 40, List.of());
            }

            String cleanedOutput = cleanGeminiText(rawOutput);

            if (!cleanedOutput.startsWith("{")) {
                boolean scam = parseVerdictText(cleanedOutput, structuralRisk);
                return new GeminiAnalysis(scam, List.of(
                        scam
                                ? "Why blocked: Gemini flagged this page as suspicious based on the supplied URL and page text."
                                : "Why blocked: Gemini did not identify strong scam indicators in the supplied URL and page text.",
                        "Modus operandi: No structured explanation was returned, so local safeguards will continue monitoring URL and content signals."
                ));
            }

            JsonNode analysisNode = objectMapper.readTree(cleanedOutput);
            String verdict = analysisNode.path("verdict").asText("").trim().toUpperCase(Locale.ROOT);
            String whyFlagged = analysisNode.path("whyFlagged").asText("").trim();
            String modusOperandi = analysisNode.path("modusOperandi").asText("").trim();
            boolean scam = parseVerdictText(verdict, structuralRisk);

            List<String> reasons = new ArrayList<>();
            if (!whyFlagged.isBlank()) {
                reasons.add("Why blocked: " + whyFlagged);
            }
            if (!modusOperandi.isBlank()) {
                reasons.add("Modus operandi: " + modusOperandi);
            }

            return new GeminiAnalysis(scam, reasons);
        } catch (IOException e) {
            System.err.println("[ScamShield Parser] Error parsing Gemini analysis response: " + e.getMessage());
            return new GeminiAnalysis(structuralRisk >= 40, List.of());
        }
    }

    private Map<String, Object> buildAnalysisRequestBody(String normalizedDomain, String pageText, int structuralRisk, String languageName) {
        String systemInstructionPrompt =
            "You are a cybersecurity expert specializing in phishing and scam detection. " +
            "Analyze the following domain and page content for signs of phishing, impersonation, or scam. " +
            "Consider domain spoofing, typosquatting, misspelled brand names, typo-filled forms, fake login forms, suspicious URLs, urgency, credential requests, free-aid or free-device bait, Telegram/WhatsApp contact collection, and application typos such as aplly. " +
            "Write whyFlagged and modusOperandi in " + languageName + ". " +
            "Respond with compact JSON only, no markdown, using this schema: " +
            "{\"verdict\":\"SCAM or SAFE\",\"whyFlagged\":\"one sentence explaining the strongest evidence\",\"modusOperandi\":\"one sentence explaining how the scam works\"}.";

        String analyticalPayload = String.format(
            "Domain: %s\nStructural risk score: %d/100\nPage Text: %s",
            normalizedDomain,
            structuralRisk,
            truncate(pageText, 800)
        );

        Map<String, Object> requestBodyMap = new HashMap<>();
        Map<String, Object> systemInstruction = new HashMap<>();
        systemInstruction.put("parts", Collections.singletonList(Map.of("text", systemInstructionPrompt)));
        requestBodyMap.put("systemInstruction", systemInstruction);
        requestBodyMap.put("contents", Collections.singletonList(Map.of(
            "role", "user",
            "parts", Collections.singletonList(Map.of("text", analyticalPayload))
        )));
        requestBodyMap.put("generationConfig", Map.of(
            "temperature", 0.0,
            "maxOutputTokens", 260,
            "responseMimeType", "application/json"
        ));
        return requestBodyMap;
    }

    private GeminiAnalysis buildRuleBasedAnalysis(int structuralRisk, String normalizedDomain, String pageText) {
        String normalizedPageText = pageText == null ? "" : pageText.toLowerCase(Locale.ROOT);
        long applicationBaitCount = APPLICATION_SCAM_BAIT_TERMS.stream()
                .filter(term -> normalizedDomain.contains(term) || normalizedPageText.contains(term))
                .count();
        boolean hasSuspiciousApplicationHost = SUSPICIOUS_APPLICATION_HOST_TERMS.stream()
                .anyMatch(term -> normalizedDomain.contains(term));

        if (applicationBaitCount >= 2 && hasSuspiciousApplicationHost && structuralRisk >= 80) {
            return new GeminiAnalysis(true, List.of(
                    "Why blocked: The untrusted domain combines public-aid or free-device bait with suspicious application wording or typo-like host text.",
                    "Modus operandi: The page appears to lure users into a fake application flow before collecting contact details, identity information, OTPs, or payment details."
            ));
        }

        if (structuralRisk >= 80) {
            return new GeminiAnalysis(true, List.of(
                    "Why blocked: The site combines high-risk scam signals such as suspicious domain wording, free-aid or device bait, typo-heavy text, or personal-contact collection.",
                    "Modus operandi: The page appears designed to lure users into submitting personal details or messaging an operator before the scammer requests more sensitive information."
            ));
        }

        if (structuralRisk >= 50) {
            return new GeminiAnalysis(false, List.of(
                    "Why blocked: Some suspicious signals were detected, but the evidence is not strong enough for a full block.",
                    "Modus operandi: Scammers often use this pattern to build trust before asking for credentials, OTPs, or contact details."
            ));
        }

        return new GeminiAnalysis(false, List.of(
                "Why blocked: No major scam indicators were detected in the available URL and page text.",
                "Modus operandi: No clear scam workflow was identified from the scanned content."
        ));
    }

    public int assessStructuralRisk(String domain, String pageText) {
        String normalizedDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);
        return calculateStructuralRisk(normalizedDomain, pageText);
    }

    private int calculateStructuralRisk(String normalizedDomain, String pageText) {
        if (normalizedDomain.isBlank()) {
            return 50;
        }

        if (isTrustedDomain(normalizedDomain)) {
            return 0;
        }

        boolean targetsMalaysianBank = BANK_KEYWORDS.stream()
                .anyMatch(normalizedDomain::contains);

        boolean possibleBankTypo = isPossibleBankTypo(normalizedDomain);

        boolean hasSuspiciousToken = SUSPICIOUS_DOMAIN_TOKENS.stream()
                .anyMatch(normalizedDomain::contains);

        boolean highRiskTld = HIGH_RISK_TLDS.stream()
                .anyMatch(normalizedDomain::endsWith);

        boolean establishedMalaysianTld = normalizedDomain.endsWith(".my");

        String normalizedPageText = pageText == null ? "" : pageText.toLowerCase(Locale.ROOT);
        boolean asksForSensitiveInfo = normalizedPageText.contains("otp")
                || normalizedPageText.contains("password")
                || normalizedPageText.contains("login")
                || normalizedPageText.contains("verify your account")
                || normalizedPageText.contains("akaun")
                || normalizedPageText.contains("kata laluan");

        boolean hasSuspiciousCopyTypo = SUSPICIOUS_COPY_TYPOS.stream()
                .anyMatch(normalizedPageText::contains);

        boolean hasApplicationScamBait = APPLICATION_SCAM_BAIT_TERMS.stream()
                .anyMatch(term -> normalizedDomain.contains(term) || normalizedPageText.contains(term));

        boolean collectsPersonalContact = PERSONAL_CONTACT_TERMS.stream()
                .anyMatch(normalizedPageText::contains);

        if (targetsMalaysianBank && hasSuspiciousToken) {
            return 100;
        }

        if (possibleBankTypo && (hasSuspiciousToken || highRiskTld || asksForSensitiveInfo)) {
            return 90;
        }

        if (hasSuspiciousCopyTypo && asksForSensitiveInfo) {
            return 75;
        }

        if (hasApplicationScamBait && collectsPersonalContact && hasSuspiciousCopyTypo) {
            return 92;
        }

        if (hasApplicationScamBait && collectsPersonalContact) {
            return 85;
        }

        if (targetsMalaysianBank && establishedMalaysianTld) {
            return 60;
        }

        if (targetsMalaysianBank) {
            return 90;
        }

        if (possibleBankTypo) {
            return 65;
        }

        if (hasSuspiciousToken && highRiskTld) {
            return 85;
        }

        if (hasSuspiciousToken && asksForSensitiveInfo) {
            return 70;
        }

        if (highRiskTld && asksForSensitiveInfo) {
            return 60;
        }

        if (hasSuspiciousCopyTypo && (hasSuspiciousToken || highRiskTld)) {
            return 55;
        }
        if (credentialSignal) {
            return 35;
        }
        return 10;
    }

    public boolean isConfigured() {
        return apiKey != null && !apiKey.isBlank();
    }

    private Map<String, Object> buildRequestBody(String domain, String pageText, UrlRiskAssessment structuralAssessment) {
        String systemPrompt = """
                You are a Malaysian financial fraud analyst for NiScamKe.
                Assess whether a URL is phishing or scam content targeting Malaysian users.
                Pay special attention to Bank Islam, Be U, Maybank, CIMB, RHB, Public Bank,
                FPX, OTP, TAC, KWSP, LHDN, parcel delivery, fraudulent aid, and investment scams.
                Return only valid JSON with these fields:
                verdict: SCAM or SAFE
                confidence: number from 0.0 to 1.0
                threatType: BANKING_PHISHING, INVESTMENT_SCAM, GOVERNMENT_IMPERSONATION, PARCEL_SCAM, CREDENTIAL_HARVESTING, SAFE, or UNKNOWN
                indicators: short array of concrete evidence strings
                malaysianContext: one short sentence
                aiExplanation: one short sentence for a non-technical user
                """;

        String structuralSummary = structuralAssessment == null
                ? "No structural assessment provided."
                : String.format(
                        Locale.ROOT,
                        "Structural score: %d. Threat type: %s. Indicators: %s. Score breakdown: %s.",
                        structuralAssessment.score(),
                        structuralAssessment.threatType(),
                        structuralAssessment.indicators(),
                        structuralAssessment.scoreBreakdown());

        String userPayload = String.format(
                "Domain: %s%nPage text: %s%n%s",
                domain,
                truncate(pageText, 1200),
                structuralSummary);

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("systemInstruction", Map.of("parts", Collections.singletonList(Map.of("text", systemPrompt))));
        requestBody.put("contents", Collections.singletonList(Map.of(
                "role", "user",
                "parts", Collections.singletonList(Map.of("text", userPayload)))));
        requestBody.put("generationConfig", Map.of(
                "temperature", 0.0,
                "maxOutputTokens", 320,
                "responseMimeType", "application/json"));
        return requestBody;
    }

    private GeminiAnalysisResult parseGeminiResponse(String responseBody, UrlRiskAssessment structuralAssessment) {
        try {
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode textNode = root.path("candidates").path(0).path("content").path("parts").path(0).path("text");
            if (textNode.isMissingNode() || textNode.asText().isBlank()) {
                log.warn("Gemini response did not include candidate text.");
                return fallbackAnalysis(structuralAssessment, "Gemini returned no text.");
            }

            String responseText = stripJsonFence(textNode.asText());
            JsonNode verdictJson = objectMapper.readTree(responseText);
            String verdict = verdictJson.path("verdict").asText("SAFE").trim().toUpperCase(Locale.ROOT);
            String threatType = verdictJson.path("threatType").asText(
                    structuralAssessment == null ? "UNKNOWN" : structuralAssessment.threatType());

            return new GeminiAnalysisResult(
                    "SCAM".equals(verdict),
                    clamp(verdictJson.path("confidence").asDouble(0.70)),
                    normalizeThreatType(threatType),
                    readIndicators(verdictJson.path("indicators")),
                    verdictJson.path("malaysianContext").asText("Malaysian context was considered."),
                    verdictJson.path("aiExplanation").asText("Gemini completed the phishing assessment."));
        } catch (IOException ex) {
            log.warn("Unable to parse Gemini JSON response: {}", ex.getMessage());
            return parseSingleWordFallback(responseBody, structuralAssessment);
        }
    }

    private GeminiAnalysisResult parseSingleWordFallback(String responseBody, UrlRiskAssessment structuralAssessment) {
        String normalized = responseBody.toUpperCase(Locale.ROOT).replaceAll("[^A-Z]", "");
        boolean scam = normalized.contains("SCAM");
        return new GeminiAnalysisResult(
                scam,
                scam ? 0.80 : 0.65,
                structuralAssessment == null ? (scam ? "UNKNOWN" : "SAFE") : structuralAssessment.threatType(),
                scam ? List.of("Gemini returned a scam verdict.") : List.of("Gemini returned a safe verdict."),
                "Gemini response was simplified, but still usable.",
                scam ? "AI flagged this URL as suspicious." : "AI did not find enough scam evidence.");
    }

    private GeminiAnalysisResult fallbackAnalysis(UrlRiskAssessment structuralAssessment, String explanation) {
        return new GeminiAnalysisResult(
                false,
                0.55,
                structuralAssessment == null ? "UNKNOWN" : structuralAssessment.threatType(),
                List.of(explanation),
                "AI result unavailable.",
                explanation);
    }

    private boolean isTrustedDomain(String normalizedDomain) {
        return TRUSTED_DOMAINS.stream()
                .anyMatch(trustedDomain -> normalizedDomain.equals(trustedDomain)
                        || normalizedDomain.endsWith("." + trustedDomain))
                || normalizedDomain.endsWith(".gov.my")
                || normalizedDomain.endsWith(".edu.my");
    }

    public void connectToGemini() {
        String fullUrl = GEMINI_API_URL + (apiKey == null ? "<missing-key>" : apiKey);
        System.out.println("[ScamShield Init] Gemini API endpoint target configured: " + fullUrl);
    }

    private static RestTemplate createRestTemplate() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
        requestFactory.setReadTimeout(READ_TIMEOUT_MILLIS);
        return new RestTemplate(requestFactory);
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders standardHeaders = new HttpHeaders();
        standardHeaders.setContentType(MediaType.APPLICATION_JSON);
        return standardHeaders;
    }

    private String resolveApiKey() {
        if (apiKey != null && !apiKey.isBlank()) {
            return apiKey.trim();
        }

        String environmentKey = System.getenv("GEMINI_API_KEY");
        if (environmentKey != null && !environmentKey.isBlank()) {
            return environmentKey.trim();
        }

        String systemPropertyKey = System.getProperty("GEMINI_API_KEY");
        return systemPropertyKey == null ? "" : systemPropertyKey.trim();
    }

    private String buildGeminiUrl(String resolvedApiKey) {
        return GEMINI_API_URL + UriUtils.encodeQueryParam(resolvedApiKey, java.nio.charset.StandardCharsets.UTF_8);
    }

    private boolean isRetryableStatus(HttpStatusCode status) {
        return status.value() == 429 || status.is5xxServerError();
    }

    private String resolveLanguageName(String targetLanguage) {
        if (targetLanguage == null || targetLanguage.isBlank()) {
            return "English";
        }

        return switch (targetLanguage.trim().toLowerCase(Locale.ROOT)) {
            case "ms", "my", "malay", "bahasa", "bahasa malaysia", "bahasa melayu" -> "Bahasa Malaysia";
            case "zh", "zh-cn", "zh-hans", "chinese", "mandarin" -> "Simplified Chinese";
            case "ta", "tamil" -> "Tamil";
            default -> "English";
        };
    }

    private String truncate(String text, int maxLength) {
        if (text == null) {
            return "";
        }
        return text.length() > maxLength ? text.substring(0, maxLength) : text;
    }

    private String cleanGeminiText(String rawOutput) {
        String cleanedOutput = rawOutput
                .replaceAll("(?i)^```json\\s*", "")
                .replaceAll("(?i)^```\\s*", "")
                .replaceAll("\\s*```$", "")
                .trim();

        int jsonStart = cleanedOutput.indexOf('{');
        int jsonEnd = cleanedOutput.lastIndexOf('}');
        if (jsonStart >= 0 && jsonEnd > jsonStart) {
            return cleanedOutput.substring(jsonStart, jsonEnd + 1);
        }

        return cleanedOutput;
    }

    private boolean parseVerdictText(String text, int structuralRisk) {
        String normalized = text == null ? "" : text.trim().toUpperCase(Locale.ROOT).replaceAll("[^A-Z]", "");
        if (normalized.contains("SCAM")) {
            return true;
        }
        if (normalized.contains("SAFE")) {
            return false;
        }
        return structuralRisk >= 40;
    }
}

