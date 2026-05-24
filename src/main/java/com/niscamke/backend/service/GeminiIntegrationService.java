package com.niscamke.backend.service;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
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

    private static final String GEMINI_API_URL_FORMAT =
            "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s";
    private static final int CONNECT_TIMEOUT_MILLIS = (int) Duration.ofSeconds(4).toMillis();
    private static final int READ_TIMEOUT_MILLIS = (int) Duration.ofSeconds(8).toMillis();
    private static final int MAX_ATTEMPTS = 2;

    @Value("${gemini.api.key:}")
    private String apiKey = "";

    @Value("${gemini.api.model:gemini-2.5-flash-lite}")
    private String model = "gemini-2.5-flash-lite";

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final UrlFeatureExtractorService urlFeatureExtractorService;

    public GeminiIntegrationService() {
        this(createRestTemplate(), new ObjectMapper(), new UrlFeatureExtractorService());
    }

    GeminiIntegrationService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this(restTemplate, objectMapper, new UrlFeatureExtractorService());
    }

    private GeminiIntegrationService(
            RestTemplate restTemplate,
            ObjectMapper objectMapper,
            UrlFeatureExtractorService urlFeatureExtractorService) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.urlFeatureExtractorService = urlFeatureExtractorService;
    }

    public record GeminiAnalysis(boolean scam, List<String> reasons) {
    }

    public record GeminiAnalysisResult(
            boolean scam,
            double confidence,
            String threatType,
            List<String> indicators,
            String malaysianContext,
            String aiExplanation) {
    }

    public boolean analyzeWithGemini(String domain, String pageText) {
        return analyzeWithGeminiDetails(domain, pageText).scam();
    }

    public GeminiAnalysis analyzeWithGeminiDetails(String domain, String pageText) {
        return analyzeWithGeminiDetails(domain, pageText, "en");
    }

    public GeminiAnalysis analyzeWithGeminiDetails(String domain, String pageText, String targetLanguage) {
        UrlRiskAssessment structuralAssessment = assessUrl(domain, pageText);

        if (structuralAssessment.score() == 0) {
            return new GeminiAnalysis(false, List.of(
                    "Trusted official domain. Still verify the URL before entering sensitive details."));
        }

        String resolvedApiKey = resolveApiKey();
        if (resolvedApiKey.isBlank()) {
            return buildRuleBasedAnalysis(structuralAssessment);
        }

        String endpoint = buildGeminiUrl(resolvedApiKey);
        Map<String, Object> requestBody = buildAnalysisRequestBody(
                structuralAssessment.domain().isBlank() ? domain : structuralAssessment.domain(),
                pageText,
                structuralAssessment.score(),
                resolveLanguageName(targetLanguage));

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                ResponseEntity<String> response = restTemplate.postForEntity(
                        endpoint,
                        new HttpEntity<>(requestBody, jsonHeaders()),
                        String.class);

                if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                    return parseGeminiAnalysisResponse(response.getBody(), structuralAssessment.score());
                }

                if (!isRetryableStatus(response.getStatusCode()) || attempt == MAX_ATTEMPTS) {
                    log.warn("Gemini returned HTTP status {}", response.getStatusCode());
                    break;
                }
            } catch (HttpStatusCodeException ex) {
                if (!isRetryableStatus(ex.getStatusCode()) || attempt == MAX_ATTEMPTS) {
                    log.warn("Gemini HTTP error: {}", ex.getStatusCode());
                    break;
                }
            } catch (RestClientException ex) {
                log.warn("Gemini request failed: {}", ex.getMessage());
                break;
            }
        }

        return buildRuleBasedAnalysis(structuralAssessment);
    }

    public int assessStructuralRisk(String domain, String pageText) {
        return assessUrl(domain, pageText).score();
    }

    public boolean isConfigured() {
        return !resolveApiKey().isBlank();
    }

    public String translateUiText(String text, String targetLanguage) {
        if (text == null || text.isBlank()) {
            return "";
        }

        String resolvedApiKey = resolveApiKey();
        if (resolvedApiKey.isBlank()) {
            return text;
        }

        String languageName = resolveLanguageName(targetLanguage);
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("systemInstruction", Map.of("parts", Collections.singletonList(Map.of(
                "text",
                "Translate the user interface text to " + languageName
                        + ". Return only the translated text, no extra explanation."))));
        requestBody.put("contents", Collections.singletonList(Map.of(
                "role",
                "user",
                "parts",
                Collections.singletonList(Map.of("text", text)))));
        requestBody.put("generationConfig", Map.of("temperature", 0.0, "maxOutputTokens", 160));

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    buildGeminiUrl(resolvedApiKey),
                    new HttpEntity<>(requestBody, jsonHeaders()),
                    String.class);
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                String translated = extractGeminiText(response.getBody()).trim();
                return translated.isBlank() ? text : translated;
            }
        } catch (IOException | RestClientException ex) {
            log.warn("Gemini translation failed: {}", ex.getMessage());
        }

        return text;
    }

    public void connectToGemini() {
        log.info("Gemini endpoint configured for model {}: {}", model, buildGeminiUrl("<key-hidden>"));
    }

    private UrlRiskAssessment assessUrl(String domainOrUrl, String pageText) {
        return urlFeatureExtractorService.assess(domainOrUrl, pageText);
    }

    private Map<String, Object> buildAnalysisRequestBody(
            String normalizedDomain,
            String pageText,
            int structuralRisk,
            String languageName) {
        String systemInstructionPrompt =
                "You are a Malaysian financial fraud analyst for NiScamKe. "
                        + "Check the URL and page text for phishing, banking impersonation, OTP/TAC theft, "
                        + "fake aid or reward applications, parcel scams, investment scams, and suspicious contact collection. "
                        + "Write whyFlagged and modusOperandi in " + languageName + ". "
                        + "Respond with compact JSON only, no markdown, using this schema: "
                        + "{\"verdict\":\"SCAM or SAFE\",\"whyFlagged\":\"one sentence explaining the strongest evidence\","
                        + "\"modusOperandi\":\"one sentence explaining how the scam works\"}.";

        String analyticalPayload = String.format(
                Locale.ROOT,
                "Domain: %s%nStructural risk score: %d/100%nPage Text: %s",
                normalizedDomain == null ? "" : normalizedDomain.toLowerCase(Locale.ROOT),
                structuralRisk,
                truncate(pageText, 1200));

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("systemInstruction", Map.of(
                "parts",
                Collections.singletonList(Map.of("text", systemInstructionPrompt))));
        requestBody.put("contents", Collections.singletonList(Map.of(
                "role",
                "user",
                "parts",
                Collections.singletonList(Map.of("text", analyticalPayload)))));
        requestBody.put("generationConfig", Map.of(
                "temperature",
                0.0,
                "maxOutputTokens",
                260,
                "responseMimeType",
                "application/json"));
        return requestBody;
    }

    private GeminiAnalysis buildRuleBasedAnalysis(UrlRiskAssessment assessment) {
        if (assessment.score() >= 80 && isAidOrRewardScam(assessment)) {
            return new GeminiAnalysis(true, List.of(
                    "Why blocked: The untrusted page combines public-aid or free-device bait with suspicious application wording.",
                    "Modus operandi: Victims are encouraged to apply or claim a reward before sharing contact details, identity data, OTPs, or payment details."));
        }

        if (assessment.score() >= 80) {
            return new GeminiAnalysis(true, List.of(
                    "Why blocked: Strong scam indicators were detected in the URL structure or page content.",
                    "Modus operandi: The page appears designed to push users into sharing sensitive banking or personal information."));
        }

        if (assessment.score() >= 50) {
            return new GeminiAnalysis(false, List.of(
                    "Why flagged: Some suspicious signals were detected, but the evidence is not strong enough for an automatic block.",
                    "Modus operandi: Scammers often use these patterns to build trust before asking for credentials, OTPs, or payment details."));
        }

        return new GeminiAnalysis(false, List.of(
                "Why allowed: No major scam indicators were detected in the available URL and page text.",
                "Modus operandi: No clear scam workflow was identified from the scanned content."));
    }

    private boolean isAidOrRewardScam(UrlRiskAssessment assessment) {
        return assessment.scoreBreakdown().containsKey("aidOrRewardApplicationScam")
                || assessment.scoreBreakdown().containsKey("aidOrRewardBait")
                || "AID_OR_REWARD_SCAM".equals(assessment.threatType());
    }

    private GeminiAnalysis parseGeminiAnalysisResponse(String responseBody, int structuralRisk) {
        try {
            String rawOutput = extractGeminiText(responseBody);
            if (rawOutput.isBlank()) {
                return buildRuleBasedAnalysisForScore(structuralRisk);
            }

            String cleanedOutput = stripJsonFence(rawOutput);
            if (!cleanedOutput.startsWith("{")) {
                boolean scam = parseVerdictText(cleanedOutput, structuralRisk);
                return new GeminiAnalysis(scam, List.of(
                        scam
                                ? "Why blocked: Gemini flagged this page as suspicious based on the supplied URL and page text."
                                : "Why allowed: Gemini did not identify strong scam indicators in the supplied URL and page text.",
                        "Modus operandi: No structured explanation was returned, so local safeguards will continue monitoring URL and content signals."));
            }

            JsonNode analysisNode = objectMapper.readTree(cleanedOutput);
            String verdict = analysisNode.path("verdict").asText("").trim().toUpperCase(Locale.ROOT);
            String whyFlagged = analysisNode.path("whyFlagged").asText("").trim();
            String modusOperandi = analysisNode.path("modusOperandi").asText("").trim();
            boolean scam = parseVerdictText(verdict, structuralRisk);

            List<String> reasons = new ArrayList<>();
            if (!whyFlagged.isBlank()) {
                reasons.add((scam ? "Why blocked: " : "Why allowed: ") + whyFlagged);
            }
            if (!modusOperandi.isBlank()) {
                reasons.add("Modus operandi: " + modusOperandi);
            }
            if (reasons.isEmpty()) {
                reasons.add(scam
                        ? "Why blocked: Gemini returned a scam verdict."
                        : "Why allowed: Gemini returned a safe verdict.");
            }

            return new GeminiAnalysis(scam, reasons);
        } catch (IOException ex) {
            log.warn("Unable to parse Gemini response: {}", ex.getMessage());
            return buildRuleBasedAnalysisForScore(structuralRisk);
        }
    }

    private GeminiAnalysis buildRuleBasedAnalysisForScore(int structuralRisk) {
        return new GeminiAnalysis(
                structuralRisk >= 80,
                List.of("Gemini response was unavailable, so NiScamKe used its local risk score as a failsafe."));
    }

    private String extractGeminiText(String responseBody) throws IOException {
        JsonNode root = objectMapper.readTree(responseBody);
        JsonNode textNode = root.path("candidates").path(0).path("content").path("parts").path(0).path("text");
        return textNode.isMissingNode() || textNode.isNull() ? "" : textNode.asText();
    }

    private String stripJsonFence(String rawOutput) {
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
        return structuralRisk >= 80;
    }

    private static RestTemplate createRestTemplate() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
        requestFactory.setReadTimeout(READ_TIMEOUT_MILLIS);
        return new RestTemplate(requestFactory);
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
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
        String safeModel = model == null || model.isBlank() ? "gemini-2.5-flash-lite" : model.trim();
        return String.format(
                GEMINI_API_URL_FORMAT,
                safeModel,
                UriUtils.encodeQueryParam(resolvedApiKey, java.nio.charset.StandardCharsets.UTF_8));
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
}
