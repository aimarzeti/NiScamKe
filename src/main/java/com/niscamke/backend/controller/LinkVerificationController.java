// LinkVerificationController.java
// for handling link verification requests from the frontend

// use package com.niscamke.backend.controller for organizing controllers in the backend
package com.niscamke.backend.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.niscamke.backend.service.VerificationService;

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

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ReportRequest {
        private String url;
        private String reporterEmail; // optional
        private String scamType;      // "PHISHING", "INVESTMENT_SCAM", "PARCEL_SCAM"
        private String description;
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("NiScamKe Backend v1.0 — Protecting Malaysians 🛡️");
    }
}
