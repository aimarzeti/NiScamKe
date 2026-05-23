package com.niscamke.backend.controller;

import java.time.LocalDateTime;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.niscamke.backend.model.DecisionLog;
import com.niscamke.backend.model.FalsePositiveReport;
import com.niscamke.backend.service.ThreatAnalyticsService;
import com.niscamke.backend.service.ThreatAnalyticsService.DailyTrendPoint;
import com.niscamke.backend.service.ThreatAnalyticsService.DashboardStatsResponse;
import com.niscamke.backend.service.ThreatAnalyticsService.DetailedHealthResponse;
import com.niscamke.backend.service.ThreatAnalyticsService.ThreatFeedItem;
import com.niscamke.backend.service.ThreatAnalyticsService.ThreatTypeStat;
import com.niscamke.backend.service.VerificationService;
import com.niscamke.backend.service.VerificationService.SummaryResponse;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@CrossOrigin(originPatterns = {"http://localhost:*", "https://localhost:*", "chrome-extension://*"})
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class LinkVerificationController {

    private final VerificationService verificationService;
    private final ThreatAnalyticsService threatAnalyticsService;

    @Value("${niscamke.partner.api-key:demo-partner-key}")
    private String partnerApiKey;

    @PostMapping("/verify-link")
    public ResponseEntity<VerificationResponse> verifyLink(@RequestBody VerificationRequest request) {
        VerificationResponse response = verificationService.checkLink(request);
        return ResponseEntity.ok(response);
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class VerificationRequest {
        private String currentUrl;
        private String pageText;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class VerificationResponse {
        private String status;
        private String reason;
    }

    @PostMapping("/report-scam")
    public ResponseEntity<String> reportScam(@RequestBody ReportRequest request) {
        verificationService.submitCommunityReport(request);
        return ResponseEntity.ok("Report submitted. Thank you for keeping Malaysia safe!");
    }

    @PostMapping("/scan-url")
    public ResponseEntity<ScanResponse> scanUrl(@RequestBody ScanRequest request) {
        return ResponseEntity.ok(verificationService.scanUrl(request));
    }

    @PostMapping("/partner/scan-link")
    public ResponseEntity<PartnerScanResponse> scanPartnerLink(
            @RequestHeader(value = "X-NISCAMKE-PARTNER-KEY", required = false) String apiKey,
            @RequestHeader(value = "X-NISCAMKE-PARTNER-ID", required = false) String partnerIdHeader,
            @RequestBody PartnerScanRequest request) {
        if (!isValidPartnerApiKey(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(PartnerScanResponse.unauthorized());
        }

        PartnerScanRequest safeRequest = request == null ? new PartnerScanRequest() : request;
        ScanRequest scanRequest = new ScanRequest(
                safeRequest.getUrl(),
                buildPartnerPageText(safeRequest),
                safeRequest.getClientTimestamp());
        ScanResponse scanResponse = verificationService.scanUrl(scanRequest);

        String partnerId = firstNonBlank(partnerIdHeader, safeRequest.getPartnerId(), "UNKNOWN_PARTNER");
        String channel = normalizePartnerChannel(safeRequest.getChannel());
        return ResponseEntity.ok(mapPartnerScanResponse(scanResponse, partnerId, channel));
    }

    @PostMapping("/report-url")
    public ResponseEntity<ReportResponse> reportUrl(@RequestBody ReportRequest request) {
        verificationService.submitCommunityReport(request);
        return ResponseEntity.ok(new ReportResponse("RECEIVED", "Report submitted and queued for trust review."));
    }

    @PostMapping("/false-positive")
    public ResponseEntity<ReportResponse> reportFalsePositive(@RequestBody FalsePositiveRequest request) {
        String message = verificationService.submitFalsePositiveReport(
                request.getUrl(),
                request.getReporterEmail(),
                request.getDecisionId(),
                request.getReason());
        return ResponseEntity.ok(new ReportResponse("RECEIVED", message));
    }

    @GetMapping("/false-positive")
    public ResponseEntity<java.util.List<FalsePositiveResponse>> getFalsePositiveReports(
            @RequestParam(value = "status", required = false) String status) {
        java.util.List<FalsePositiveResponse> responses = verificationService.getFalsePositiveReports(status).stream()
                .map(this::mapFalsePositiveResponse)
                .toList();
        return ResponseEntity.ok(responses);
    }

    @PatchMapping("/false-positive/{id}/status")
    public ResponseEntity<FalsePositiveResponse> reviewFalsePositive(
            @PathVariable("id") Long id,
            @RequestBody FalsePositiveReviewRequest request) {
        return verificationService.reviewFalsePositiveReport(id, request.getStatus(), request.getReviewNote())
                .map(this::mapFalsePositiveResponse)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/decision/{id}")
    public ResponseEntity<DecisionResponse> getDecision(@PathVariable("id") String id) {
        return verificationService.findDecisionByPublicId(id)
                .map(this::mapDecisionResponse)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/admin/summary")
    public ResponseEntity<SummaryResponse> getAdminSummary() {
        return ResponseEntity.ok(verificationService.getSummary());
    }

    @GetMapping("/admin/recent-decisions")
    public ResponseEntity<java.util.List<DecisionResponse>> getRecentDecisions() {
        java.util.List<DecisionResponse> responses = verificationService.getRecentDecisions().stream()
                .map(this::mapDecisionResponse)
                .toList();
        return ResponseEntity.ok(responses);
    }

    @GetMapping("/stats/dashboard")
    public ResponseEntity<DashboardStatsResponse> getDashboardStats() {
        return ResponseEntity.ok(threatAnalyticsService.getDashboardStats());
    }

    @GetMapping("/stats/threats")
    public ResponseEntity<java.util.List<ThreatFeedItem>> getRecentThreats() {
        return ResponseEntity.ok(threatAnalyticsService.getRecentThreats());
    }

    @GetMapping("/stats/trends")
    public ResponseEntity<java.util.List<DailyTrendPoint>> getThreatTrends() {
        return ResponseEntity.ok(threatAnalyticsService.getSevenDayTrends());
    }

    @GetMapping("/stats/threat-types")
    public ResponseEntity<java.util.List<ThreatTypeStat>> getThreatTypes() {
        return ResponseEntity.ok(threatAnalyticsService.getThreatTypeBreakdown());
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ReportRequest {
        private String url;
        private String reporterEmail; // optional
        private String scamType;      // "PHISHING", "INVESTMENT_SCAM", "PARCEL_SCAM"
        private String description;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ScanRequest {
        private String url;
        private String pageText;
        private String clientTimestamp;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ScanResponse {
        private String decisionId;
        private String decision;
        private Integer riskScore;
        private Double confidence;
        private java.util.List<String> reasons;
        private String evidenceSources;
        private Integer ttlSeconds;
        private String threatType;
        private String aiExplanation;
        private String scoreBreakdown;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PartnerScanRequest {
        private String partnerId;
        private String channel; // BANKING_APP, EWALLET, UNIVERSITY_PORTAL, TELCO_APP, MOBILE_WEB
        private String url;
        private String pageText;
        private String userJourney; // EXTERNAL_LINK, IN_APP_BROWSER, PUSH_NOTIFICATION, SMS_DEEP_LINK
        private String clientTimestamp;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PartnerScanResponse {
        private String apiVersion;
        private String partnerId;
        private String channel;
        private String decisionId;
        private String decision;
        private String recommendedAction;
        private String userMessage;
        private Integer riskScore;
        private Double confidence;
        private java.util.List<String> reasons;
        private String threatType;
        private String evidenceSources;
        private Integer ttlSeconds;
        private String scannedAt;

        public static PartnerScanResponse unauthorized() {
            return new PartnerScanResponse(
                    "partner-v1",
                    "UNKNOWN_PARTNER",
                    "UNKNOWN",
                    null,
                    "UNAUTHORIZED",
                    "REJECT_REQUEST",
                    "Missing or invalid partner API key.",
                    null,
                    null,
                    java.util.List.of("Partner authentication failed."),
                    "UNKNOWN",
                    "PARTNER_AUTH",
                    0,
                    LocalDateTime.now().toString());
        }
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ReportResponse {
        private String status;
        private String message;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DecisionResponse {
        private String decisionId;
        private String url;
        private String domain;
        private String decision;
        private Integer riskScore;
        private Double confidence;
        private String reason;
        private String evidenceSources;
        private String threatType;
        private String aiExplanation;
        private String scoreBreakdown;
        private String createdAt;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FalsePositiveRequest {
        private String url;
        private String decisionId;
        private String reporterEmail;
        private String reason;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FalsePositiveReviewRequest {
        private String status; // APPROVED or REJECTED
        private String reviewNote;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FalsePositiveResponse {
        private Long id;
        private String url;
        private String domainName;
        private String decisionId;
        private String reporterEmail;
        private String reason;
        private String status;
        private String reviewNote;
        private String createdAt;
        private String reviewedAt;
    }

    private DecisionResponse mapDecisionResponse(DecisionLog log) {
        return new DecisionResponse(
                log.getPublicId(),
                log.getUrl(),
                log.getDomainName(),
                log.getDecision(),
                log.getRiskScore(),
                log.getConfidence(),
                log.getReason(),
                log.getEvidenceSources(),
                log.getThreatType(),
                log.getAiExplanation(),
                log.getScoreBreakdown(),
                log.getCreatedAt().toString());
    }

    private FalsePositiveResponse mapFalsePositiveResponse(FalsePositiveReport report) {
        return new FalsePositiveResponse(
                report.getId(),
                report.getUrl(),
                report.getDomainName(),
                report.getDecisionId(),
                report.getReporterEmail(),
                report.getReason(),
                report.getStatus(),
                report.getReviewNote(),
                report.getCreatedAt() == null ? null : report.getCreatedAt().toString(),
                report.getReviewedAt() == null ? null : report.getReviewedAt().toString());
    }

    private boolean isValidPartnerApiKey(String apiKey) {
        return apiKey != null && !apiKey.isBlank() && apiKey.equals(partnerApiKey);
    }

    private String buildPartnerPageText(PartnerScanRequest request) {
        return String.join(" ",
                firstNonBlank(request.getPageText(), ""),
                "partnerChannel=" + normalizePartnerChannel(request.getChannel()),
                "userJourney=" + firstNonBlank(request.getUserJourney(), "UNKNOWN"));
    }

    private PartnerScanResponse mapPartnerScanResponse(ScanResponse scanResponse, String partnerId, String channel) {
        String decision = scanResponse.getDecision() == null ? "WARN" : scanResponse.getDecision();
        return new PartnerScanResponse(
                "partner-v1",
                partnerId,
                channel,
                scanResponse.getDecisionId(),
                decision,
                recommendedPartnerAction(decision),
                partnerUserMessage(decision),
                scanResponse.getRiskScore(),
                scanResponse.getConfidence(),
                scanResponse.getReasons(),
                scanResponse.getThreatType(),
                scanResponse.getEvidenceSources(),
                scanResponse.getTtlSeconds(),
                LocalDateTime.now().toString());
    }

    private String recommendedPartnerAction(String decision) {
        return switch (normalizeDecision(decision)) {
            case "BLOCK" -> "BLOCK_AND_SHOW_INTERSTITIAL";
            case "WARN" -> "SHOW_WARNING_BEFORE_OPEN";
            default -> "OPEN_LINK";
        };
    }

    private String partnerUserMessage(String decision) {
        return switch (normalizeDecision(decision)) {
            case "BLOCK" -> "Do not open this link. Ni Scam Ke? found strong scam or phishing indicators.";
            case "WARN" -> "Show a caution screen before opening. Remind the user not to enter OTP, TAC, passwords, or card details.";
            default -> "No major scam indicators found. Continue normal in-app safety reminders.";
        };
    }

    private String normalizeDecision(String decision) {
        String normalized = decision == null ? "WARN" : decision.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "ALLOW", "WARN", "BLOCK" -> normalized;
            default -> "WARN";
        };
    }

    private String normalizePartnerChannel(String channel) {
        String normalized = channel == null ? "MOBILE_APP" : channel.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "BANKING_APP", "EWALLET", "UNIVERSITY_PORTAL", "TELCO_APP", "MOBILE_WEB", "MOBILE_APP" -> normalized;
            default -> "MOBILE_APP";
        };
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return "";
        }

        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }

        return "";
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("NiScamKe Backend v1.0 - Protecting Malaysians");
    }

    @GetMapping("/health/detailed")
    public ResponseEntity<DetailedHealthResponse> detailedHealth() {
        return ResponseEntity.ok(threatAnalyticsService.getDetailedHealth());
    }
}
