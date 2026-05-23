package com.niscamke.backend.service;

import java.io.IOException;
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

    private static final String GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=";

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

    @Value("${gemini.api.model:gemini-2.0-flash}")
    private String model;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public record GeminiAnalysis(boolean scam, List<String> reasons) {
    }

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
            String targetUrlEndpoint = GEMINI_API_URL + apiKey;
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
                (pageText != null && pageText.length() > 800) ? pageText.substring(0, 800) : pageText
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
                "maxOutputTokens", 260
            ));

            HttpHeaders standardHeaders = new HttpHeaders();
            standardHeaders.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> outboundHttpRequestEntity = new HttpEntity<>(requestBodyMap, standardHeaders);
            ResponseEntity<String> externalServiceApiResponse = restTemplate.postForEntity(targetUrlEndpoint, outboundHttpRequestEntity, String.class);

            if (externalServiceApiResponse.getStatusCode() == HttpStatus.OK && externalServiceApiResponse.getBody() != null) {
                GeminiAnalysis analysis = parseGeminiAnalysisResponse(externalServiceApiResponse.getBody(), structuralRisk);
                if (!analysis.reasons().isEmpty()) {
                    return analysis;
                }
            } else {
                System.err.println("[ScamShield] Unexpected HTTP status: " + externalServiceApiResponse.getStatusCode());
            }
        } catch (RestClientException e) {
            System.err.println("[ScamShield System Fault] Gemini API Connection Error: " + e.getMessage());
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

    private GeminiAnalysis parseGeminiAnalysisResponse(String responseBody, int structuralRisk) {
        try {
            String rawOutput = extractGeminiText(responseBody);
            if (rawOutput.isBlank()) {
                return new GeminiAnalysis(structuralRisk >= 40, List.of());
            }

            String cleanedOutput = rawOutput
                    .replaceAll("(?i)^```json\\s*", "")
                    .replaceAll("(?i)^```\\s*", "")
                    .replaceAll("\\s*```$", "")
                    .trim();

            JsonNode analysisNode = objectMapper.readTree(cleanedOutput);
            String verdict = analysisNode.path("verdict").asText("").trim().toUpperCase(Locale.ROOT);
            String whyFlagged = analysisNode.path("whyFlagged").asText("").trim();
            String modusOperandi = analysisNode.path("modusOperandi").asText("").trim();
            boolean scam = "SCAM".equals(verdict) || structuralRisk >= 40;

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

        String languageName = "English";

        if (apiKey == null || apiKey.isBlank()) {
            return text;
        }

        try {
            String targetUrlEndpoint = GEMINI_API_URL + apiKey;
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

            HttpHeaders standardHeaders = new HttpHeaders();
            standardHeaders.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> outboundHttpRequestEntity = new HttpEntity<>(requestBodyMap, standardHeaders);
            ResponseEntity<String> externalServiceApiResponse = restTemplate.postForEntity(targetUrlEndpoint, outboundHttpRequestEntity, String.class);

            if (externalServiceApiResponse.getStatusCode() == HttpStatus.OK && externalServiceApiResponse.getBody() != null) {
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

