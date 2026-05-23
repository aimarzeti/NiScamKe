package com.niscamke.backend.service;

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

    private static final Set<String> TRUSTED_DOMAINS = Set.of(
        "bankislam.com.my", "cimbclicks.com.my", "maybank2u.com.my",
        "rhbbank.com.my", "pbebank.com", "beubankislam.com.my"
    );

    @Value("${gemini.api.key}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public boolean analyzeWithGemini(String domain, String pageText) {
        String normalizedDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);

        int structuralRisk = calculateStructuralRisk(normalizedDomain);
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
                "Consider: domain spoofing (similar to legitimate banks), fake login forms, suspicious URLs, urgency tactics, requests for credentials. " +
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

        } catch (Exception e) {
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

        } catch (Exception e) {
            System.err.println("[ScamShield Parser] Error parsing Gemini response: " + e.getMessage());
            return false;
        }
    }

    public int assessStructuralRisk(String domain, String pageText) {
        String normalizedDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);
        return calculateStructuralRisk(normalizedDomain);
    }

    private int calculateStructuralRisk(String normalizedDomain) {
        boolean targetsMalaysianBank = BANK_KEYWORDS.stream()
                .anyMatch(normalizedDomain::contains);

        boolean trustedMalaysianDomain = TRUSTED_DOMAINS.contains(normalizedDomain)
                || normalizedDomain.endsWith(".gov.my")
                || normalizedDomain.endsWith(".edu.my")
                || normalizedDomain.endsWith(".com.my");

        return (targetsMalaysianBank && !trustedMalaysianDomain) ? 100 : 0;
    }

    public void connectToGemini() {
        String fullUrl = GEMINI_API_URL + (apiKey == null ? "<missing-key>" : apiKey);
        System.out.println("[ScamShield Init] Gemini API endpoint target configured: " + fullUrl);
    }
}