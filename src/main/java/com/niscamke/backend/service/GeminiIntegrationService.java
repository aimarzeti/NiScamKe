package com.niscamke.backend.service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
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

    @Value("${gemini.api.key}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public boolean analyzeWithGemini(String domain, String pageText) {
        String normalizedDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);

        // 1. Fast-Path Local Validation (Geng bank tiruan)
        boolean targetsMalaysianBank = normalizedDomain.contains("bimb")
                || normalizedDomain.contains("cimb")
                || normalizedDomain.contains("maybank")
                || normalizedDomain.contains("secure");

        boolean trustedMalaysianDomain = normalizedDomain.endsWith(".com.my")
                || normalizedDomain.endsWith(".my");

        if (targetsMalaysianBank && !trustedMalaysianDomain) {
            System.out.println("[ScamShield Fast-Path] Structural bank mimic detected. Hard-blocking threat.");
            return true; 
        }

        // 2. Fallback to Live AI Analysis (Person 2 - Live Google Gemini Call)
        if (apiKey == null || apiKey.isBlank()) {
            System.err.println("[ScamShield Warning] Missing Gemini API key parameter config.");
            return false;
        }

        try {
            String targetUrlEndpoint = GEMINI_API_URL + apiKey;

            // System instructions to force a single-word answer from Gemini
            String systemInstructionPrompt = 
                "You are an expert cyber threat intelligence analyst for Be U by Bank Islam. " +
                "Evaluate whether the following target is a phishing scam targeting consumers. " +
                "CRITICAL DIRECTION: Your reply must be exactly a single word token: either 'SCAM' or 'SAFE'. No spaces, no markdown.";

            String analyticalPayload = String.format(
                "Domain: %s\nText: %s",
                normalizedDomain,
                (pageText != null && pageText.length() > 800) ? pageText.substring(0, 800) : pageText
            );

            // Constructing Google's required nested JSON body structure
            Map<String, Object> requestBodyMap = new HashMap<>();
            Map<String, Object> textPart = new HashMap<>();
            textPart.put("text", systemInstructionPrompt + "\n\n" + analyticalPayload);
            
            Map<String, Object> partsMap = new HashMap<>();
            partsMap.put("parts", Collections.singletonList(textPart));
            requestBodyMap.put("contents", Collections.singletonList(partsMap));

            // Set content headers
            HttpHeaders standardHeaders = new HttpHeaders();
            standardHeaders.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> outboundHttpRequestEntity = new HttpEntity<>(requestBodyMap, standardHeaders);

            // Send live post request to Google Cloud
            ResponseEntity<String> externalServiceApiResponse = restTemplate.postForEntity(targetUrlEndpoint, outboundHttpRequestEntity, String.class);

            // Parse response body if request is successful (HTTP 200)
            if (externalServiceApiResponse.getStatusCode() == HttpStatus.OK && externalServiceApiResponse.getBody() != null) {
                JsonNode parsedRootNode = objectMapper.readTree(externalServiceApiResponse.getBody());
                String structuralAiResponseOutput = parsedRootNode
                        .path("candidates").get(0)
                        .path("content").path("parts").get(0)
                        .path("text").asText().trim();

                System.out.println("[ScamShield Engine] Gemini response received: " + structuralAiResponseOutput);

                // Return true if Gemini tags it as a SCAM
                return "SCAM".equalsIgnoreCase(structuralAiResponseOutput);
            }

        } catch (Exception e) {
            System.err.println("[ScamShield System Fault] Gemini API Connection Error: " + e.getMessage());
        }

        return false;
    }

    public void connectToGemini() {
        String fullUrl = GEMINI_API_URL + apiKey;
        System.out.println("[ScamShield Init] Gemini API endpoint target configured.");
    }
}