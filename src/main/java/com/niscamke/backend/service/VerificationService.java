package com.niscamke.backend.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
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
import com.niscamke.backend.service.GeminiIntegrationService.GeminiAnalysisResult;
import com.niscamke.backend.service.UrlFeatureExtractorService.UrlRiskAssessment;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class VerificationService {

    private static final int BLOCK_THRESHOLD = 80;
    private static final int WARN_THRESHOLD = 45;

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
                request == null ? null : request.getCurrentUrl(),
                request == null ? null : request.getPageText(),
                null);
        ScanResponse response = scanUrl(scanRequest);
        return new VerificationResponse(response.getDecision(), String.join(" ", response.getReasons()));
    }

    public ScanResponse scanUrl(ScanRequest request) {
        String requestedUrl = request == null ? "" : trimToEmpty(request.getUrl());
        String pageText = request == null ? "" : request.getPageText();
        UrlRiskAssessment assessment = urlFeatureExtractorService.assess(requestedUrl, pageText);

        if (assessment.domain().isBlank()) {
            DecisionLog invalidLog = saveDecision(
                    requestedUrl.isBlank() ? "unknown" : requestedUrl,
                    "unknown",
                    "WARN",
                    50,
                    0.40,
                    "Malformed URL. Unable to verify safely.",
                    "INPUT_VALIDATION",
                    "UNKNOWN",
                    "URL parsing failed before AI analysis.",
                    Map.of("malformedUrl", 50));
            return mapLogToScanResponse(invalidLog, List.of("Malformed URL. Unable to verify safely."), 300);
        }

        Optional<ScamRegistry> registryEntry = scamRegistryRepository.findByDomainName(assessment.domain());
        if (registryEntry.isPresent()) {
            String threatType = normalizeThreatType(registryEntry.get().getScamType());
            DecisionLog log = saveDecision(
                    assessment.normalizedUrl(),
                    assessment.domain(),
                    "BLOCK",
                    95,
                    0.97,
                    "Known scam domain from community intelligence.",
                    "COMMUNITY_DB,RULE_ENGINE",
                    threatType,
                    "This domain is already listed in the NiScamKe scam registry.",
                    assessment.scoreBreakdown());
            return mapLogToScanResponse(log, List.of("Known scam domain from community intelligence."), 300);
        }

        ScanDecision decision = decideWithTwoTierPipeline(assessment, pageText);
        DecisionLog log = saveDecision(
                assessment.normalizedUrl(),
                assessment.domain(),
                decision.decision(),
                decision.riskScore(),
                decision.confidence(),
                decision.reason(),
                decision.evidenceSources(),
                decision.threatType(),
                decision.aiExplanation(),
                assessment.scoreBreakdown());

        if ("BLOCK".equals(decision.decision())
                && decision.confidence() >= 0.80
                && assessment.score() >= BLOCK_THRESHOLD) {
            saveToRegistry(assessment.domain(), decision.threatType(), decision.reason());
        }

        return mapLogToScanResponse(log, decision.reasons(), decision.ttlSeconds());
    }

    private ScanDecision decideWithTwoTierPipeline(UrlRiskAssessment assessment, String pageText) {
        if (assessment.score() >= BLOCK_THRESHOLD) {
            String reason = "High-risk Malaysian phishing pattern detected before AI call.";
            return new ScanDecision(
                    "BLOCK",
                    assessment.score(),
                    0.92,
                    reason,
                    withPrimaryReason(reason, assessment.indicators()),
                    "RULE_ENGINE",
                    assessment.threatType(),
                    "Deterministic URL features were strong enough to block without spending AI quota.",
                    300);
        }

        if (assessment.score() < 15) {
            String reason = "No strong phishing indicators detected.";
            return new ScanDecision(
                    "ALLOW",
                    Math.max(5, assessment.score()),
                    0.93,
                    reason,
                    withPrimaryReason(reason, assessment.indicators()),
                    "RULE_ENGINE",
                    "SAFE",
                    "Low-risk URL structure, so Gemini was skipped for speed.",
                    300);
        }

        GeminiAnalysisResult aiResult = geminiIntegrationService.analyzeWithGemini(
                assessment.domain(),
                pageText,
                assessment);

        if (aiResult.isScam()) {
            int riskScore = Math.max(BLOCK_THRESHOLD, Math.max(assessment.score(), (int) Math.round(aiResult.confidence() * 100)));
            String reason = firstNonBlank(aiResult.aiExplanation(), "Gemini flagged this URL as a likely scam.");
            return new ScanDecision(
                    "BLOCK",
                    Math.min(100, riskScore),
                    Math.max(0.80, aiResult.confidence()),
                    reason,
                    withPrimaryReason(reason, combineIndicators(assessment.indicators(), aiResult.indicators())),
                    "AI_MODEL,RULE_ENGINE",
                    normalizeThreatType(aiResult.threatType()),
                    aiResult.malaysianContext(),
                    300);
        }

        if (assessment.score() >= WARN_THRESHOLD) {
            String reason = "Suspicious URL structure detected, but AI did not confirm a scam verdict.";
            return new ScanDecision(
                    "WARN",
                    assessment.score(),
                    Math.max(0.65, aiResult.confidence()),
                    reason,
                    withPrimaryReason(reason, combineIndicators(assessment.indicators(), aiResult.indicators())),
                    "AI_MODEL,RULE_ENGINE",
                    assessment.threatType(),
                    aiResult.aiExplanation(),
                    180);
        }

        String reason = "AI and structural analysis did not find enough scam evidence.";
        return new ScanDecision(
                "ALLOW",
                assessment.score(),
                Math.max(0.82, aiResult.confidence()),
                reason,
                withPrimaryReason(reason, combineIndicators(assessment.indicators(), aiResult.indicators())),
                "AI_MODEL,RULE_ENGINE",
                "SAFE",
                aiResult.aiExplanation(),
                300);
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
        registryEntry.setReportedBy(firstNonBlank(request.getReporterEmail(), "COMMUNITY"));
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

    private List<String> withPrimaryReason(String reason, List<String> indicators) {
        List<String> reasons = new ArrayList<>();
        reasons.add(reason);
        indicators.stream()
                .filter(indicator -> indicator != null && !indicator.isBlank())
                .limit(4)
                .forEach(reasons::add);
        return reasons;
    }

    private List<String> combineIndicators(List<String> structuralIndicators, List<String> aiIndicators) {
        List<String> combined = new ArrayList<>();
        if (structuralIndicators != null) {
            combined.addAll(structuralIndicators);
        }
        if (aiIndicators != null) {
            combined.addAll(aiIndicators);
        }
        return combined;
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
                    "AI_DETECTED" -> normalized;
            default -> "UNKNOWN";
        };
    }

    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private String trimToEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private record ScanDecision(
            String decision,
            int riskScore,
            double confidence,
            String reason,
            List<String> reasons,
            String evidenceSources,
            String threatType,
            String aiExplanation,
            int ttlSeconds) {
    }
}
