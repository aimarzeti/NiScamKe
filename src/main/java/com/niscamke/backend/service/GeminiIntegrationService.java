package com.niscamke.backend.service;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

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

/**
 * SCAMSHIELD AI - DEEP CORE REASONING ENGINE (PERSON 2)
 * Core service integrating Google Gemini API for advanced phishing detection.
 */
@Service
public class GeminiIntegrationService {

    private static final String GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=";
    private static final int GEMINI_MAX_ATTEMPTS = 2;
    private static final int CONNECT_TIMEOUT_MILLIS = (int) Duration.ofSeconds(3).toMillis();
    private static final int READ_TIMEOUT_MILLIS = (int) Duration.ofSeconds(8).toMillis();

    private static final List<String> BANK_KEYWORDS = List.of(
        "bimb", "bankislam", "cimb", "maybank", "rhb", "hongleong",
        "publicbank", "ambank", "affin", "bsn", "agro"
    );

    private static final List<String> BANK_LOOKALIKE_TERMS = List.of(
        "maybank", "maybank2u", "cimb", "cimbclicks", "bankislam",
        "bimb", "rhb", "rhbbank", "hongleong", "hongleongbank",
        "publicbank", "pbebank", "ambank", "affin", "bsn",
        "mybsn", "agrobank"
    );

    private static final List<String> SUSPICIOUS_DOMAIN_TOKENS = List.of(
        "secure", "login", "verify", "update", "support", "account", "otp", "claim"
    );

    private static final List<String> APPLICATION_SCAM_BAIT_TERMS = List.of(
        "bantuan", "percuma", "free", "claim", "laptop", "phone",
        "subsidi", "sumbangan", "rahmah", "emadani", "hadiah"
    );

    private static final List<String> SUSPICIOUS_APPLICATION_HOST_TERMS = List.of(
        "apy", "ap1", "app1y", "aplly", "aply", "apply", "mohon", "daftar", "claim"
    );

    private static final List<String> PERSONAL_CONTACT_TERMS = List.of(
        "nama penuh", "nombor telegram", "telegram", "whatsapp",
        "jantina", "no telefon", "nombor telefon", "phone number",
        "kad pengenalan", "identity card"
    );

    private static final List<String> SUSPICIOUS_COPY_TYPOS = List.of(
        "securty", "securrity", "verfy", "verifcation", "verificaton",
        "accout", "acount", "passw0rd", "pasword", "logln", "l0gin",
        "immediatly", "suspention", "restricton", "unathorized",
        "aplly", "aply", "app1y", "appy now"
    );

    private static final List<String> HIGH_RISK_TLDS = List.of(
        ".click", ".online", ".site", ".top", ".xyz", ".icu", ".test"
    );

    private static final Set<String> TRUSTED_DOMAINS = Set.of(
        "bankislam.com.my", "cimbclicks.com.my", "maybank2u.com.my",
        "rhbbank.com.my", "pbebank.com", "beubankislam.com.my",
        "maybank.com", "cimb.com.my", "publicbank.com.my",
        "hongleongbank.com.my", "mybsn.com.my"
    );

    @Value("${gemini.api.key:}")
    private String apiKey;

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
        return analyzeWithGeminiDetails(domain, pageText).scam();
    }

    public GeminiAnalysis analyzeWithGeminiDetails(String domain, String pageText) {
        return analyzeWithGeminiDetails(domain, pageText, "en");
    }

    public GeminiAnalysis analyzeWithGeminiDetails(String domain, String pageText, String targetLanguage) {
        String normalizedDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);
        int structuralRisk = calculateStructuralRisk(normalizedDomain, pageText);
        String languageName = resolveLanguageName(targetLanguage);
        String resolvedApiKey = resolveApiKey();

        if (resolvedApiKey.isBlank()) {
            System.err.println("[ScamShield Warning] Missing Gemini API key parameter config.");
            return buildRuleBasedAnalysis(structuralRisk, normalizedDomain, pageText);
        }

        String targetUrlEndpoint = buildGeminiUrl(resolvedApiKey);
        HttpEntity<Map<String, Object>> outboundHttpRequestEntity = new HttpEntity<>(
                buildAnalysisRequestBody(normalizedDomain, pageText, structuralRisk, languageName),
                jsonHeaders());

        for (int attempt = 1; attempt <= GEMINI_MAX_ATTEMPTS; attempt++) {
            try {
                ResponseEntity<String> externalServiceApiResponse = restTemplate.postForEntity(targetUrlEndpoint, outboundHttpRequestEntity, String.class);

                if (externalServiceApiResponse.getStatusCode().is2xxSuccessful() && externalServiceApiResponse.getBody() != null) {
                    GeminiAnalysis analysis = parseGeminiAnalysisResponse(externalServiceApiResponse.getBody(), structuralRisk);
                    if (!analysis.reasons().isEmpty()) {
                        return analysis;
                    }
                    System.err.println("[ScamShield Parser] Gemini response did not contain enough usable analysis.");
                    break;
                }

                System.err.println("[ScamShield] Unexpected Gemini HTTP status: " + externalServiceApiResponse.getStatusCode());
                if (!isRetryableStatus(externalServiceApiResponse.getStatusCode())) {
                    break;
                }
            } catch (RestClientException e) {
                System.err.println("[ScamShield System Fault] Gemini API attempt " + attempt + " failed: " + e.getMessage());
            }
        }

        return buildRuleBasedAnalysis(structuralRisk, normalizedDomain, pageText);
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

    public String translateUiText(String text, String targetLanguage) {
        if (text == null || text.isBlank()) {
            return "";
        }

        String languageName = resolveLanguageName(targetLanguage);
        String resolvedApiKey = resolveApiKey();

        if (resolvedApiKey.isBlank()) {
            return text;
        }

        try {
            String targetUrlEndpoint = buildGeminiUrl(resolvedApiKey);
            String systemInstructionPrompt =
                "You translate browser safety UI copy for a Malaysian anti-scam extension. " +
                "Translate the user's text into " + languageName + ". Keep cybersecurity meaning accurate, concise, and natural. " +
                "Do not add explanations. Return only the translated text.";

            Map<String, Object> requestBodyMap = new HashMap<>();
            Map<String, Object> systemInstruction = new HashMap<>();
            systemInstruction.put("parts", Collections.singletonList(Map.of("text", systemInstructionPrompt)));
            requestBodyMap.put("systemInstruction", systemInstruction);
            requestBodyMap.put("contents", Collections.singletonList(Map.of(
                "role", "user",
                "parts", Collections.singletonList(Map.of("text", text.length() > 700 ? text.substring(0, 700) : text))
            )));
            requestBodyMap.put("generationConfig", Map.of(
                "temperature", 0.1,
                "maxOutputTokens", 140
            ));

            HttpEntity<Map<String, Object>> outboundHttpRequestEntity = new HttpEntity<>(requestBodyMap, jsonHeaders());
            ResponseEntity<String> externalServiceApiResponse = restTemplate.postForEntity(targetUrlEndpoint, outboundHttpRequestEntity, String.class);

            if (externalServiceApiResponse.getStatusCode().is2xxSuccessful() && externalServiceApiResponse.getBody() != null) {
                String translated = extractGeminiText(externalServiceApiResponse.getBody());
                return translated.isBlank() ? text : translated;
            }
        } catch (RestClientException | IOException e) {
            System.err.println("[ScamShield Translation] Gemini translation unavailable: " + e.getMessage());
        }

        return text;
    }

    private String extractGeminiText(String responseBody) throws IOException {
        JsonNode parsedRootNode = objectMapper.readTree(responseBody);
        JsonNode textNode = parsedRootNode.path("candidates").path(0).path("content").path("parts").path(0).path("text");
        return textNode.isMissingNode() || textNode.isNull() ? "" : textNode.asText().trim();
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
        long applicationBaitCount = APPLICATION_SCAM_BAIT_TERMS.stream()
                .filter(term -> normalizedDomain.contains(term) || normalizedPageText.contains(term))
                .count();

        boolean collectsPersonalContact = PERSONAL_CONTACT_TERMS.stream()
                .anyMatch(normalizedPageText::contains);

        boolean hasSuspiciousApplicationHost = SUSPICIOUS_APPLICATION_HOST_TERMS.stream()
                .anyMatch(normalizedDomain::contains);

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

        if (applicationBaitCount >= 2 && hasSuspiciousApplicationHost) {
            return 90;
        }

        if (applicationBaitCount >= 3 && !establishedMalaysianTld) {
            return 85;
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

        return 10;
    }

    private boolean isPossibleBankTypo(String normalizedDomain) {
        String simplifiedDomain = normalizedDomain.replaceAll("[^a-z0-9]", "");

        for (String term : BANK_LOOKALIKE_TERMS) {
            if (term.length() <= 4) {
                continue;
            }

            if (!simplifiedDomain.contains(term) && containsNearMatch(simplifiedDomain, term, 2)) {
                return true;
            }
        }

        return false;
    }

    private boolean containsNearMatch(String text, String target, int threshold) {
        int targetLength = target.length();
        int minLength = Math.max(1, targetLength - threshold);
        int maxLength = Math.min(text.length(), targetLength + threshold);

        for (int length = minLength; length <= maxLength; length++) {
            for (int index = 0; index + length <= text.length(); index++) {
                String candidate = text.substring(index, index + length);
                if (levenshteinDistance(candidate, target) <= threshold) {
                    return true;
                }
            }
        }

        return false;
    }

    private int levenshteinDistance(String first, String second) {
        int[] previous = new int[second.length() + 1];
        int[] current = new int[second.length() + 1];

        for (int index = 0; index <= second.length(); index++) {
            previous[index] = index;
        }

        for (int firstIndex = 1; firstIndex <= first.length(); firstIndex++) {
            current[0] = firstIndex;
            for (int secondIndex = 1; secondIndex <= second.length(); secondIndex++) {
                int substitutionCost = first.charAt(firstIndex - 1) == second.charAt(secondIndex - 1) ? 0 : 1;
                current[secondIndex] = Math.min(
                        Math.min(current[secondIndex - 1] + 1, previous[secondIndex] + 1),
                        previous[secondIndex - 1] + substitutionCost);
            }

            int[] temp = previous;
            previous = current;
            current = temp;
        }

        return previous[second.length()];
    }

    private boolean isTrustedDomain(String normalizedDomain) {
        return TRUSTED_DOMAINS.stream()
                .anyMatch(trustedDomain -> normalizedDomain.equals(trustedDomain)
                        || normalizedDomain.endsWith("." + trustedDomain))
                || normalizedDomain.endsWith(".gov.my")
                || normalizedDomain.endsWith(".edu.my");
    }

    public void connectToGemini() {
        String resolvedApiKey = resolveApiKey();
        String fullUrl = GEMINI_API_URL + (resolvedApiKey.isBlank() ? "<missing-key>" : "<configured>");
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

