package com.niscamke.backend.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.niscamke.backend.controller.LinkVerificationController.ReportRequest;
import com.niscamke.backend.controller.LinkVerificationController.ScanRequest;
import com.niscamke.backend.controller.LinkVerificationController.ScanResponse;
import com.niscamke.backend.controller.LinkVerificationController.VerificationRequest;
import com.niscamke.backend.controller.LinkVerificationController.VerificationResponse;
import com.niscamke.backend.model.DecisionLog;
import com.niscamke.backend.model.FalsePositiveReport;
import com.niscamke.backend.model.ScamRegistry;
import com.niscamke.backend.model.UserReport;
import com.niscamke.backend.repository.DecisionLogRepository;
import com.niscamke.backend.repository.FalsePositiveReportRepository;
import com.niscamke.backend.repository.ScamRegistryRepository;
import com.niscamke.backend.repository.UserReportRepository;
import com.niscamke.backend.service.GeminiIntegrationService.GeminiAnalysis;
import com.niscamke.backend.service.UrlFeatureExtractorService.UrlRiskAssessment;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class VerificationService {

    private static final int BLOCK_THRESHOLD = 80;
    private static final int WARN_THRESHOLD = 50;
    private static final int SCAN_TTL_SECONDS = 300;

    private final ScamRegistryRepository scamRegistryRepository;
    private final DecisionLogRepository decisionLogRepository;
    private final UserReportRepository userReportRepository;
    private final FalsePositiveReportRepository falsePositiveReportRepository;
    private final GeminiIntegrationService geminiIntegrationService;
    private final UrlFeatureExtractorService urlFeatureExtractorService;
    private final ObjectMapper objectMapper;

    @Cacheable(value = "domainVerifications", key = "#request.currentUrl + ':' + #request.pageText")
    public VerificationResponse checkLink(VerificationRequest request) {
        ScanRequest scanRequest = new ScanRequest(
                request == null ? "" : request.getCurrentUrl(),
                request == null ? "" : request.getPageText(),
                null,
                "en");
        ScanResponse scanResponse = scanUrl(scanRequest);
        String reason = scanResponse.getReasons() == null || scanResponse.getReasons().isEmpty()
                ? "Scan completed."
                : scanResponse.getReasons().get(0);
        return new VerificationResponse(scanResponse.getDecision(), reason);
    }

    public ScanResponse scanUrl(ScanRequest request) {
        String normalizedUrl = request == null || request.getUrl() == null ? "" : request.getUrl().trim();
        String pageText = request == null ? "" : request.getPageText();
        String targetLanguage = request == null ? "en" : request.getTargetLanguage();

        UrlRiskAssessment structuralAssessment = urlFeatureExtractorService.assess(normalizedUrl, pageText);
        String domain = structuralAssessment.domain();
        if (domain.isBlank()) {
            DecisionLog invalid = saveDecision(
                    normalizedUrl.isBlank() ? "unknown" : normalizedUrl,
                    "unknown",
                    "WARN",
                    50,
                    0.40,
                    "Malformed URL. Unable to verify safely.",
                    "INPUT_VALIDATION",
                    "UNKNOWN",
                    "The URL could not be parsed safely.",
                    Map.of("inputValidation", 50));
            return mapLogToScanResponse(
                    invalid,
                    List.of("Malformed URL. Unable to verify safely."),
                    SCAN_TTL_SECONDS);
        }

        Optional<ScamRegistry> knownScamEntry = scamRegistryRepository.findByDomainName(domain);
        boolean knownScam = knownScamEntry.isPresent();
        GeminiAnalysis geminiAnalysis = knownScam
                ? new GeminiAnalysis(true, List.of("Known scam domain from community intelligence."))
                : geminiIntegrationService.analyzeWithGeminiDetails(domain, pageText, targetLanguage);

        int riskScore = calculateRiskScore(structuralAssessment.score(), knownScam, geminiAnalysis.scam());
        String decision = decisionForRisk(riskScore);
        double confidence = confidenceForDecision(decision, knownScam, geminiAnalysis.scam());
        String threatType = knownScam
                ? normalizeThreatType(knownScamEntry.get().getScamType())
                : normalizeThreatType(structuralAssessment.threatType());
        String reason = primaryReason(knownScam, geminiAnalysis, structuralAssessment, decision);
        String evidenceSources = evidenceSources(knownScam, geminiIntegrationService.isConfigured(), structuralAssessment.score());
        List<String> reasons = mergeReasons(reason, structuralAssessment.indicators(), geminiAnalysis.reasons());

        DecisionLog decisionLog = saveDecision(
                structuralAssessment.normalizedUrl(),
                domain,
                decision,
                riskScore,
                confidence,
                reason,
                evidenceSources,
                threatType,
                aiExplanationFrom(reasons),
                structuralAssessment.scoreBreakdown());

        if ("BLOCK".equals(decision) && !knownScam) {
            saveToRegistry(domain, threatType, reason);
        }

        return mapLogToScanResponse(decisionLog, reasons, SCAN_TTL_SECONDS);
    }

    public Optional<DecisionLog> findDecisionByPublicId(String decisionId) {
        return decisionLogRepository.findByPublicId(decisionId);
    }

    public String submitFalsePositiveReport(String url, String reporterEmail, String decisionId, String reason) {
        String domain = extractDomainName(url);
        if (domain.isBlank()) {
            return "Invalid URL. Unable to submit false-positive report.";
        }

        FalsePositiveReport report = Objects.requireNonNull(FalsePositiveReport.builder()
                .url(url)
                .domainName(domain)
                .decisionId(decisionId)
                .reporterEmail(reporterEmail)
                .reason(reason == null || reason.isBlank() ? "User reported false positive." : reason)
                .status("PENDING_REVIEW")
                .build());
        falsePositiveReportRepository.save(report);

        saveDecision(
                url,
                domain,
                "WARN",
                45,
                0.60,
                "False-positive report submitted by community and queued for review.",
                "FALSE_POSITIVE_REPORT",
                "UNKNOWN",
                "A user disputed this block decision.",
                Map.of("falsePositiveReport", 45));
        return "False-positive report received and queued for review.";
    }

    public List<FalsePositiveReport> getFalsePositiveReports(String status) {
        if (status == null || status.isBlank()) {
            return falsePositiveReportRepository.findAll();
        }
        return falsePositiveReportRepository.findByStatus(status.trim().toUpperCase(Locale.ROOT));
    }

    public Optional<FalsePositiveReport> reviewFalsePositiveReport(long reportId, String newStatus, String reviewNote) {
        return falsePositiveReportRepository.findById(reportId).map(report -> {
            String status = (newStatus == null ? "" : newStatus.trim().toUpperCase(Locale.ROOT));
            if (!"APPROVED".equals(status) && !"REJECTED".equals(status)) {
                throw new IllegalArgumentException("False-positive status must be APPROVED or REJECTED.");
            }

            report.setStatus(status);
            report.setReviewNote(reviewNote);
            report.setReviewedAt(LocalDateTime.now());

            if ("APPROVED".equals(status)) {
                scamRegistryRepository.findByDomainName(report.getDomainName())
                        .ifPresent(scamRegistryRepository::delete);
            }

            saveDecision(
                    report.getUrl(),
                    report.getDomainName(),
                    "APPROVED".equals(status) ? "ALLOW" : "BLOCK",
                    "APPROVED".equals(status) ? 20 : 85,
                    0.85,
                    "False-positive report " + status.toLowerCase(Locale.ROOT) + " by reviewer.",
                    "MODERATOR_REVIEW",
                    "UNKNOWN",
                    "Human moderator review updated the trust decision.",
                    Map.of("moderatorReview", "APPROVED".equals(status) ? 20 : 85));

            falsePositiveReportRepository.save(report);
            return report;
        });
    }

    public SummaryResponse getSummary() {
        long allowCount = decisionLogRepository.countByDecision("ALLOW");
        long warnCount = decisionLogRepository.countByDecision("WARN");
        long blockCount = decisionLogRepository.countByDecision("BLOCK");
        long totalScans = allowCount + warnCount + blockCount;
        long pendingFalsePositives = falsePositiveReportRepository.countByStatus("PENDING_REVIEW");
        long approvedFalsePositives = falsePositiveReportRepository.countByStatus("APPROVED");
        long rejectedFalsePositives = falsePositiveReportRepository.countByStatus("REJECTED");
        return new SummaryResponse(
                totalScans,
                allowCount,
                warnCount,
                blockCount,
                pendingFalsePositives,
                approvedFalsePositives,
                rejectedFalsePositives,
                scamRegistryRepository.count(),
                userReportRepository.count());
    }

    public record SummaryResponse(
            long totalScans,
            long allowCount,
            long warnCount,
            long blockCount,
            long pendingFalsePositives,
            long approvedFalsePositives,
            long rejectedFalsePositives,
            long registryCount,
            long communityReportCount) {
    }

    public List<DecisionLog> getRecentDecisions() {
        return decisionLogRepository.findTop10ByOrderByCreatedAtDesc();
    }

    public void submitCommunityReport(ReportRequest request) {
        if (request == null) {
            log.warn("Ignoring null community report request.");
            return;
        }

        String url = trimToEmpty(request.getUrl());
        String domain = extractDomainName(url);
        if (domain.isBlank()) {
            log.warn("Ignoring community report with invalid URL: {}", url);
            return;
        }

        LocalDateTime now = LocalDateTime.now();
        String scamType = normalizeThreatType(request.getScamType() == null ? "COMMUNITY_REPORTED" : request.getScamType());
        String description = firstNonBlank(request.getDescription(), "Community report submitted");
        String reporterEmail = firstNonBlank(request.getReporterEmail(), "COMMUNITY");

        UserReport userReport = Objects.requireNonNull(UserReport.builder()
                .url(url)
                .domainName(domain)
                .reporterEmail(reporterEmail)
                .scamType(scamType)
                .description(description)
                .status("PENDING_REVIEW")
                .build());
        userReportRepository.save(userReport);

        ScamRegistry registryEntry = scamRegistryRepository.findByDomainName(domain)
                .orElseGet(() -> Objects.requireNonNull(ScamRegistry.builder().domainName(domain).build()));
        registryEntry.setScamType(scamType);
        registryEntry.setThreatLevel("HIGH");
        registryEntry.setDescription(description);
        registryEntry.setFlaggedAt(now);
        registryEntry.setReportedBy(reporterEmail);
        registryEntry.setReportedAt(now);
        scamRegistryRepository.save(registryEntry);

        saveDecision(
                url,
                domain,
                "WARN",
                65,
                0.70,
                "Community report submitted and queued for trust review.",
                "COMMUNITY_REPORT",
                scamType,
                "Community intelligence strengthened the risk signal for this domain.",
                Map.of("communityReport", 65));
    }

    private int calculateRiskScore(int structuralRisk, boolean knownScam, boolean analysisScam) {
        if (knownScam) {
            return 95;
        }
        if (analysisScam) {
            return Math.max(BLOCK_THRESHOLD, structuralRisk);
        }
        return structuralRisk == 0 ? 10 : structuralRisk;
    }

    private String decisionForRisk(int riskScore) {
        if (riskScore >= BLOCK_THRESHOLD) {
            return "BLOCK";
        }
        if (riskScore >= WARN_THRESHOLD) {
            return "WARN";
        }
        return "ALLOW";
    }

    private double confidenceForDecision(String decision, boolean knownScam, boolean analysisScam) {
        if (knownScam) {
            return 0.97;
        }
        if (analysisScam) {
            return 0.88;
        }
        return switch (decision) {
            case "BLOCK" -> 0.86;
            case "WARN" -> 0.74;
            default -> 0.92;
        };
    }

    private String primaryReason(
            boolean knownScam,
            GeminiAnalysis geminiAnalysis,
            UrlRiskAssessment structuralAssessment,
            String decision) {
        if (knownScam) {
            return "Known scam domain from community intelligence.";
        }
        if (geminiAnalysis.reasons() != null && !geminiAnalysis.reasons().isEmpty()) {
            return geminiAnalysis.reasons().get(0);
        }
        if ("ALLOW".equals(decision)) {
            return "No significant phishing indicators detected.";
        }
        return structuralAssessment.indicators().isEmpty()
                ? "Suspicious scam indicators were detected."
                : structuralAssessment.indicators().get(0);
    }

    private String evidenceSources(boolean knownScam, boolean geminiConfigured, int structuralRisk) {
        if (knownScam) {
            return "COMMUNITY_DB,RULE_ENGINE";
        }
        if (geminiConfigured) {
            return structuralRisk > 0 ? "AI_MODEL,RULE_ENGINE" : "AI_MODEL";
        }
        return structuralRisk > 0 ? "RULE_ENGINE" : "RULE_ENGINE";
    }

    private List<String> mergeReasons(String primary, List<String> structuralIndicators, List<String> geminiReasons) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        if (primary != null && !primary.isBlank()) {
            merged.add(primary);
        }
        if (geminiReasons != null) {
            geminiReasons.stream()
                    .filter(reason -> reason != null && !reason.isBlank())
                    .limit(3)
                    .forEach(merged::add);
        }
        if (structuralIndicators != null) {
            structuralIndicators.stream()
                    .filter(reason -> reason != null && !reason.isBlank())
                    .limit(4)
                    .forEach(merged::add);
        }
        return new ArrayList<>(merged);
    }

    private String aiExplanationFrom(List<String> reasons) {
        return reasons == null || reasons.isEmpty() ? "No AI explanation was recorded." : reasons.get(0);
    }

    private void saveToRegistry(String domain, String scamType, String description) {
        scamRegistryRepository.findByDomainName(domain).ifPresentOrElse(
                existing -> {
                    existing.setScamType(normalizeThreatType(scamType));
                    existing.setThreatLevel("HIGH");
                    existing.setDescription(description);
                    existing.setFlaggedAt(LocalDateTime.now());
                    scamRegistryRepository.save(existing);
                },
                () -> {
                    LocalDateTime now = LocalDateTime.now();
                    ScamRegistry scamRegistry = ScamRegistry.builder()
                            .domainName(domain)
                            .scamType(normalizeThreatType(scamType))
                            .threatLevel("HIGH")
                            .description(description)
                            .flaggedAt(now)
                            .reportedBy("SYSTEM")
                            .reportedAt(now)
                            .build();
                    scamRegistryRepository.save(scamRegistry);
                });
    }

    private DecisionLog saveDecision(
            String url,
            String domain,
            String decision,
            int riskScore,
            double confidence,
            String reason,
            String evidenceSources,
            String threatType,
            String aiExplanation,
            Map<String, Integer> scoreBreakdown) {
        DecisionLog decisionLog = Objects.requireNonNull(DecisionLog.builder()
                .url(firstNonBlank(url, "unknown"))
                .domainName(firstNonBlank(domain, "unknown"))
                .decision(decision)
                .riskScore(Math.max(0, Math.min(100, riskScore)))
                .confidence(Math.max(0.0, Math.min(1.0, confidence)))
                .reason(firstNonBlank(reason, "Decision completed."))
                .evidenceSources(firstNonBlank(evidenceSources, "RULE_ENGINE"))
                .threatType(normalizeThreatType(threatType))
                .aiExplanation(firstNonBlank(aiExplanation, "No AI explanation was recorded."))
                .scoreBreakdown(toJson(scoreBreakdown))
                .build());
        return Objects.requireNonNull(decisionLogRepository.save(decisionLog));
    }

    private ScanResponse mapLogToScanResponse(DecisionLog log, List<String> reasons, int ttlSeconds) {
        return new ScanResponse(
                log.getPublicId(),
                log.getDecision(),
                log.getRiskScore(),
                log.getConfidence(),
                reasons,
                log.getEvidenceSources(),
                ttlSeconds,
                log.getThreatType(),
                log.getAiExplanation(),
                log.getScoreBreakdown());
    }

    private String toJson(Map<String, Integer> scoreBreakdown) {
        try {
            return objectMapper.writeValueAsString(scoreBreakdown == null ? Map.of() : scoreBreakdown);
        } catch (JsonProcessingException ex) {
            log.warn("Unable to serialize score breakdown: {}", ex.getMessage());
            return "{}";
        }
    }

    private String extractDomainName(String urlString) {
        return urlFeatureExtractorService.extractDomainName(urlString);
    }

    private String normalizeThreatType(String threatType) {
        String normalized = threatType == null ? "UNKNOWN" : threatType.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "BANKING_PHISHING", "INVESTMENT_SCAM", "GOVERNMENT_IMPERSONATION",
                    "PARCEL_SCAM", "CREDENTIAL_HARVESTING", "SAFE", "COMMUNITY_REPORTED",
                    "AI_DETECTED", "AID_OR_REWARD_SCAM" -> normalized;
            default -> "UNKNOWN";
        };
    }

    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private String trimToEmpty(String value) {
        return value == null ? "" : value.trim();
    }
}
