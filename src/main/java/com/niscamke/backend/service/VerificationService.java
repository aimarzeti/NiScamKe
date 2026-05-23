package com.niscamke.backend.service; 

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

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

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class VerificationService {

    private final ScamRegistryRepository scamRegistryRepository;
    private final DecisionLogRepository decisionLogRepository;
    private final UserReportRepository userReportRepository;
    private final FalsePositiveReportRepository falsePositiveReportRepository;
    private final GeminiIntegrationService geminiIntegrationService;

    @Cacheable(value = "domainVerifications", key = "#request.currentUrl")
public VerificationResponse checkLink(VerificationRequest request) {
        String domain = extractDomainName(request.getCurrentUrl());
        if (domain.isBlank()) {
            return new VerificationResponse("ALLOW", "Unable to verify malformed URL");
        }

        return scamRegistryRepository.findByDomainName(domain)
                .map(entry -> new VerificationResponse(
                        "BLOCK",
                        "Known scam domain in community database"))
                .orElseGet(() -> analyzeUnknownDomain(domain, request.getPageText()));
    }

    private VerificationResponse analyzeUnknownDomain(String domain, String pageText) {
        int structuralRisk = geminiIntegrationService.assessStructuralRisk(domain, pageText);
        boolean isScam = geminiIntegrationService.analyzeWithGemini(domain, pageText);

        if (isScam) {
            // ✅ Only auto-save if BOTH fast-path AND AI agree it's a scam
            if (structuralRisk >= 40) {
                saveToRegistry(domain);
            }

            return new VerificationResponse(
                    "BLOCK",
                    "AI analysis indicates this domain may be a scam. Please proceed with caution.");
        }

        return new VerificationResponse("ALLOW", "No scam indicators detected for this domain.");
    }

    public ScanResponse scanUrl(ScanRequest request) {
        String normalizedUrl = request.getUrl() == null ? "" : request.getUrl().trim();
        String domain = extractDomainName(normalizedUrl);
        if (domain.isBlank()) {
            DecisionLog invalid = DecisionLog.builder()
                    .url(normalizedUrl.isBlank() ? "unknown" : normalizedUrl)
                    .domainName("unknown")
                    .decision("WARN")
                    .riskScore(50)
                    .confidence(0.4)
                    .reason("Malformed URL. Unable to verify safely.")
                    .evidenceSources("INPUT_VALIDATION")
                    .build();
            decisionLogRepository.save(invalid);
            return mapLogToScanResponse(invalid, "WARN", List.of("Malformed URL. Unable to verify safely."), 300);
        }

        int structuralRisk = geminiIntegrationService.assessStructuralRisk(domain, request.getPageText());
        boolean knownScam = scamRegistryRepository.findByDomainName(domain).isPresent();
        boolean aiScam = knownScam || geminiIntegrationService.analyzeWithGemini(domain, request.getPageText());

        int riskScore = knownScam ? 95 : structuralRisk;
        if (!knownScam && aiScam) {
            riskScore = Math.max(70, structuralRisk);
        }
        if (!aiScam && structuralRisk == 0) {
            riskScore = 10;
        }

        String decision = riskScore >= 80 ? "BLOCK" : (riskScore >= 50 ? "WARN" : "ALLOW");
        double confidence = riskScore >= 80 ? 0.95 : (riskScore >= 50 ? 0.75 : 0.92);

        String reason = knownScam
                ? "Known scam domain from community intelligence."
                : aiScam
                ? "AI phishing analysis flagged suspicious signals."
                : "No significant phishing indicators detected.";

        String evidenceSources = knownScam ? "COMMUNITY_DB,RULE_ENGINE" : aiScam ? "AI_MODEL,RULE_ENGINE" : "RULE_ENGINE";
        DecisionLog decisionLog = DecisionLog.builder()
                .url(normalizedUrl)
                .domainName(domain)
                .decision(decision)
                .riskScore(riskScore)
                .confidence(confidence)
                .reason(reason)
                .evidenceSources(evidenceSources)
                .build();
        decisionLogRepository.save(decisionLog);

        if ("BLOCK".equals(decision) && !knownScam) {
            saveToRegistry(domain);
        }

        return mapLogToScanResponse(decisionLog, decision, List.of(reason), 300);
    }

    public Optional<DecisionLog> findDecisionByPublicId(String decisionId) {
        return decisionLogRepository.findByPublicId(decisionId);
    }

    public String submitFalsePositiveReport(String url, String reporterEmail, String decisionId, String reason) {
        String domain = extractDomainName(url);
        if (domain.isBlank()) {
            return "Invalid URL. Unable to submit false-positive report.";
        }

        FalsePositiveReport report = FalsePositiveReport.builder()
                .url(url)
                .domainName(domain)
                .decisionId(decisionId)
                .reporterEmail(reporterEmail)
                .reason(reason == null || reason.isBlank() ? "User reported false positive." : reason)
                .status("PENDING_REVIEW")
                .build();
        falsePositiveReportRepository.save(report);

        DecisionLog reportLog = DecisionLog.builder()
                .url(url)
                .domainName(domain)
                .decision("WARN")
                .riskScore(45)
                .confidence(0.6)
                .reason("False-positive report submitted by community and queued for review.")
                .evidenceSources("FALSE_POSITIVE_REPORT")
                .build();
        decisionLogRepository.save(reportLog);
        return "False-positive report received and queued for review.";
    }

    public List<FalsePositiveReport> getFalsePositiveReports(String status) {
        if (status == null || status.isBlank()) {
            return falsePositiveReportRepository.findAll();
        }
        return falsePositiveReportRepository.findByStatus(status);
    }

    public Optional<FalsePositiveReport> reviewFalsePositiveReport(long reportId, String newStatus, String reviewNote) {
        return falsePositiveReportRepository.findById(reportId).map(report -> {
            String status = (newStatus == null ? "" : newStatus.trim().toUpperCase(Locale.ROOT));
            if (!"APPROVED".equals(status) && !"REJECTED".equals(status)) {
                return report;
            }

            report.setStatus(status);
            report.setReviewNote(reviewNote);
            report.setReviewedAt(LocalDateTime.now());

            if ("APPROVED".equals(status)) {
                scamRegistryRepository.findByDomainName(report.getDomainName())
                        .ifPresent(scamRegistryRepository::delete);
            }

            DecisionLog reviewLog = DecisionLog.builder()
                    .url(report.getUrl())
                    .domainName(report.getDomainName())
                    .decision("APPROVED".equals(status) ? "ALLOW" : "BLOCK")
                    .riskScore("APPROVED".equals(status) ? 20 : 85)
                    .confidence(0.85)
                    .reason("False-positive report " + status.toLowerCase(Locale.ROOT) + " by reviewer.")
                    .evidenceSources("MODERATOR_REVIEW")
                    .build();
            decisionLogRepository.save(reviewLog);

            falsePositiveReportRepository.save(report);
            return report;
        });
    }

    public SummaryResponse getSummary() {
        long allowCount = decisionLogRepository.countByDecision("ALLOW");
        long warnCount = decisionLogRepository.countByDecision("WARN");
        long blockCount = decisionLogRepository.countByDecision("BLOCK");
        long pendingFalsePositives = falsePositiveReportRepository.countByStatus("PENDING_REVIEW");
        long approvedFalsePositives = falsePositiveReportRepository.countByStatus("APPROVED");
        long rejectedFalsePositives = falsePositiveReportRepository.countByStatus("REJECTED");
        return new SummaryResponse(
                allowCount,
                warnCount,
                blockCount,
                pendingFalsePositives,
                approvedFalsePositives,
                rejectedFalsePositives);
    }

    public record SummaryResponse(
            long allowCount,
            long warnCount,
            long blockCount,
            long pendingFalsePositives,
            long approvedFalsePositives,
            long rejectedFalsePositives) {
    }

    private void saveToRegistry(String domain) {
        LocalDateTime now = LocalDateTime.now();
        ScamRegistry scamRegistry = ScamRegistry.builder()
                .domainName(domain)
                .scamType("AI_DETECTED")
                .threatLevel("HIGH")
                .description("Automatically flagged by Gemini AI analysis")
                .flaggedAt(now)
                .reportedBy("SYSTEM")
                .reportedAt(now)
                .build();

        scamRegistryRepository.save(scamRegistry);
    }

    public void submitCommunityReport(ReportRequest request) {
        String domain = extractDomainName(request.getUrl());
        if (domain.isBlank()) {
            return;
        }

        LocalDateTime now = LocalDateTime.now();
        UserReport userReport = UserReport.builder()
                .url(request.getUrl())
                .domainName(domain)
                .reporterEmail(request.getReporterEmail())
                .scamType(request.getScamType() != null ? request.getScamType() : "COMMUNITY_REPORTED")
                .description(request.getDescription())
                .status("PENDING_REVIEW")
                .build();
        userReportRepository.save(userReport);

        ScamRegistry registryEntry = scamRegistryRepository.findByDomainName(domain)
                .orElseGet(() -> ScamRegistry.builder().domainName(domain).build());
        registryEntry.setScamType(request.getScamType() != null ? request.getScamType() : "COMMUNITY_REPORTED");
        registryEntry.setThreatLevel("HIGH");
        registryEntry.setDescription(request.getDescription() != null ? request.getDescription() : "Community report submitted");
        registryEntry.setFlaggedAt(now);
        registryEntry.setReportedBy(request.getReporterEmail() != null ? request.getReporterEmail() : "COMMUNITY");
        registryEntry.setReportedAt(now);
        scamRegistryRepository.save(registryEntry);

        DecisionLog reportLog = DecisionLog.builder()
                .url(request.getUrl())
                .domainName(domain)
                .decision("WARN")
                .riskScore(65)
                .confidence(0.7)
                .reason("Community report submitted and queued for trust review.")
                .evidenceSources("COMMUNITY_REPORT")
                .build();
        decisionLogRepository.save(reportLog);
    }

    private ScanResponse mapLogToScanResponse(DecisionLog log, String decision, List<String> reasons, int ttlSeconds) {
        return new ScanResponse(
                log.getPublicId(),
                decision,
                log.getRiskScore(),
                log.getConfidence(),
                reasons,
                log.getEvidenceSources(),
                ttlSeconds);
    }

    private String extractDomainName(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return "";
        }

        String normalizedUrl = urlString.trim();
        if (!normalizedUrl.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) {
            normalizedUrl = "https://" + normalizedUrl;
        }

        String host;
        try {
            URI uri = URI.create(normalizedUrl);
            host = uri.getHost();
        } catch (IllegalArgumentException ex) {
            return "";
        }

        if (host == null || host.isBlank()) {
            return "";
        }

        String domain = host.toLowerCase(Locale.ROOT);
        if (domain.startsWith("www.")) {
            domain = domain.substring(4);
        }

        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }

        return domain;
    }
}

