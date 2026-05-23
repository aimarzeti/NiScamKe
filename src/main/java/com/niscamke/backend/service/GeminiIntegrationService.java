package com.niscamke.backend.service;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * SCAMSHIELD AI - DEEP CORE REASONING ENGINE (PERSON 2)
 * Core service integrating Google Gemini API for advanced phishing detection.
 */
@Service
public class GeminiIntegrationService {

    private static final String GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=";

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

    private static final List<String> SUSPICIOUS_COPY_TYPOS = List.of(
        "securty", "securrity", "verfy", "verifcation", "verificaton",
        "accout", "acount", "passw0rd", "pasword", "logln", "l0gin",
        "immediatly", "suspention", "restricton", "unathorized"
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

    @Value("${gemini.api.key}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

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
                "Consider: domain spoofing (similar to legitimate banks), typosquatting, misspelled brand names, typo-filled credential requests, fake login forms, suspicious URLs, urgency tactics, requests for credentials. " +
                "If the domain or page text appears to imitate a bank with small spelling changes or suspicious typos, mark it as SCAM. " +
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

        if (targetsMalaysianBank && hasSuspiciousToken) {
            return 100;
        }

        if (possibleBankTypo && (hasSuspiciousToken || highRiskTld || asksForSensitiveInfo)) {
            return 90;
        }

        if (hasSuspiciousCopyTypo && asksForSensitiveInfo) {
            return 75;
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
        String fullUrl = GEMINI_API_URL + (apiKey == null ? "<missing-key>" : apiKey);
        System.out.println("[ScamShield Init] Gemini API endpoint target configured: " + fullUrl);
    }
}
