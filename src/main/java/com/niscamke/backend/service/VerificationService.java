package com.niscamke.backend.service; 

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Locale;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import com.niscamke.backend.controller.LinkVerificationController.ReportRequest;
import com.niscamke.backend.controller.LinkVerificationController.VerificationRequest;
import com.niscamke.backend.controller.LinkVerificationController.VerificationResponse;
import com.niscamke.backend.model.ScamRegistry;
import com.niscamke.backend.repository.ScamRegistryRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class VerificationService {

    private final ScamRegistryRepository scamRegistryRepository;
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
        scamRegistryRepository.findByDomainName(domain)
                .map(existing -> {
                    existing.setScamType(request.getScamType() != null ? request.getScamType() : "COMMUNITY_REPORTED");
                    existing.setThreatLevel("HIGH");
                    existing.setDescription(request.getDescription() != null ? request.getDescription() : "Community report submitted");
                    existing.setFlaggedAt(now);
                    existing.setReportedBy(request.getReporterEmail() != null ? request.getReporterEmail() : "COMMUNITY");
                    existing.setReportedAt(now);
                    return scamRegistryRepository.save(existing);
                })
                .orElseGet(() -> scamRegistryRepository.save(ScamRegistry.builder()
                        .domainName(domain)
                        .scamType(request.getScamType() != null ? request.getScamType() : "COMMUNITY_REPORTED")
                        .threatLevel("HIGH")
                        .description(request.getDescription() != null ? request.getDescription() : "Community report submitted")
                        .flaggedAt(now)
                        .reportedBy(request.getReporterEmail() != null ? request.getReporterEmail() : "COMMUNITY")
                        .reportedAt(now)
                        .build()));
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

