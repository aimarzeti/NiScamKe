package com.niscamke.backend.service;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

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

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public GeminiAnalysisResult analyzeWithGemini(String domain, String pageText, UrlRiskAssessment structuralAssessment) {
        if (!isConfigured()) {
            log.warn("Gemini API key is not configured. Falling back to structural URL analysis only.");
            return new GeminiAnalysisResult(
                    false,
                    0.50,
                    structuralAssessment == null ? "UNKNOWN" : structuralAssessment.threatType(),
                    List.of("Gemini API key is not configured; deterministic rules handled this scan."),
                    "AI analysis unavailable in this environment.",
                    "Gemini was skipped because GEMINI_API_KEY is not set.");
        }

        try {
            String endpoint = String.format(GEMINI_API_URL, Objects.requireNonNull(model), Objects.requireNonNull(apiKey));
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(
                    buildRequestBody(domain, pageText, structuralAssessment),
                    headers);

            ResponseEntity<String> response = restTemplate.postForEntity(endpoint, request, String.class);
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return parseGeminiResponse(response.getBody(), structuralAssessment);
            }

            log.warn("Gemini returned unexpected status {}", response.getStatusCode());
        } catch (RestClientException ex) {
            log.warn("Gemini API call failed: {}", ex.getMessage());
        }

        return new GeminiAnalysisResult(
                false,
                0.55,
                structuralAssessment == null ? "UNKNOWN" : structuralAssessment.threatType(),
                List.of("Gemini call failed; deterministic rules handled this scan."),
                "Gemini did not return a usable result.",
                "AI analysis failed open so the extension does not block legitimate browsing during outages.");
    }

    public boolean analyzeWithGemini(String domain, String pageText) {
        return analyzeWithGemini(domain, pageText, null).isScam();
    }

    public int assessStructuralRisk(String domain, String pageText) {
        String combined = (domain == null ? "" : domain) + " " + (pageText == null ? "" : pageText);
        boolean bankSignal = combined.toLowerCase(Locale.ROOT).matches(".*(maybank|cimb|bankislam|bimb|rhb|publicbank|pbebank|ambank|bsn|agro).*");
        boolean credentialSignal = combined.toLowerCase(Locale.ROOT).matches(".*(otp|tac|password|login|pin|fpx).*");
        if (bankSignal && credentialSignal) {
            return 75;
        }
        if (bankSignal) {
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
                Judge whether a URL is phishing or scam content targeting Malaysian users.
                Pay special attention to Bank Islam, Be U, Maybank, CIMB, RHB, Public Bank,
                FPX, OTP, TAC, KWSP, LHDN, parcel delivery, fake aid, and investment scams.
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

    private List<String> readIndicators(JsonNode indicatorsNode) {
        if (indicatorsNode == null || !indicatorsNode.isArray() || indicatorsNode.isEmpty()) {
            return List.of("Gemini did not return specific indicators.");
        }

        List<String> indicators = new java.util.ArrayList<>();
        indicatorsNode.forEach(node -> {
            if (!node.asText("").isBlank()) {
                indicators.add(node.asText());
            }
        });
        return indicators.isEmpty() ? List.of("Gemini did not return specific indicators.") : indicators;
    }

    private String normalizeThreatType(String threatType) {
        String normalized = threatType == null ? "UNKNOWN" : threatType.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "BANKING_PHISHING", "INVESTMENT_SCAM", "GOVERNMENT_IMPERSONATION",
                    "PARCEL_SCAM", "CREDENTIAL_HARVESTING", "SAFE" -> normalized;
            default -> "UNKNOWN";
        };
    }

    private String stripJsonFence(String text) {
        String trimmed = text.trim();
        if (trimmed.startsWith("```")) {
            trimmed = trimmed.replaceFirst("^```(?:json)?", "").replaceFirst("```$", "").trim();
        }
        return trimmed;
    }

    private double clamp(double value) {
        return Math.max(0.0, Math.min(1.0, value));
    }

    private String truncate(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    public record GeminiAnalysisResult(
            boolean isScam,
            double confidence,
            String threatType,
            List<String> indicators,
            String malaysianContext,
            String aiExplanation) {
    }
}
