// LinkVerificationController.java
// for handling link verification requests from the frontend

// use package com.niscamke.backend.controller for organizing controllers in the backend
package com.niscamke.backend.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.niscamke.backend.model.DecisionLog;
import com.niscamke.backend.model.FalsePositiveReport;
import com.niscamke.backend.service.VerificationService;
import com.niscamke.backend.service.VerificationService.SummaryResponse;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@CrossOrigin
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class LinkVerificationController {

    private final VerificationService verificationService;
    private final com.niscamke.backend.service.GeminiIntegrationService geminiIntegrationService;

    // endpoint for verifying links, accepts a POST request with the current URL and page text, returns a response with the verification status and reason
    @PostMapping("/verify-link") // endpoint for verifying links
    public ResponseEntity<VerificationResponse> verifyLink(@RequestBody VerificationRequest request) {
        VerificationResponse response = verificationService.checkLink(request);
        return ResponseEntity.ok(response);
    }

    // for calling the verification service to check the link and return the verification response
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class VerificationRequest {
        private String currentUrl;
        private String pageText;
    }

    // for returning the verification status and reason to the frontend after checking the link
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

    @PostMapping("/translate-ui")
    public ResponseEntity<TranslationResponse> translateUi(@RequestBody TranslationRequest request) {
        String translated = geminiIntegrationService.translateUiText(request.getText(), request.getTargetLanguage());
        return ResponseEntity.ok(new TranslationResponse(translated));
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
        private String targetLanguage;
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
    public static class TranslationRequest {
        private String text;
        private String targetLanguage;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TranslationResponse {
        private String translatedText;
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

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("NiScamKe Backend v1.0 - Protecting Malaysians");
    }
}
