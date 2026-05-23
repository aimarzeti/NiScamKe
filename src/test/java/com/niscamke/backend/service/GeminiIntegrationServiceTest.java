package com.niscamke.backend.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class GeminiIntegrationServiceTest {

    private final GeminiIntegrationService service = new GeminiIntegrationService();

    @Test
    void flagsUntrustedFreeLaptopApplicationBaitDomain() {
        String domain = "bantuanlaptop-percuma.apy-hy.com";
        String pageText = "Semak kelayakan bantuan laptop percuma. Aplly sekarang.";

        int riskScore = service.assessStructuralRisk(domain, pageText);
        GeminiIntegrationService.GeminiAnalysis analysis = service.analyzeWithGeminiDetails(domain, pageText);

        assertThat(riskScore).isGreaterThanOrEqualTo(80);
        assertThat(analysis.scam()).isTrue();
        assertThat(analysis.reasons()).anySatisfy(reason ->
                assertThat(reason).contains("free-device bait"));
    }

    @Test
    void doesNotFlagTrustedDomainEvenWhenPageMentionsAid() {
        String domain = "www.maybank2u.com.my";
        String pageText = "Official customer announcement about bantuan and laptop financing.";

        int riskScore = service.assessStructuralRisk(domain, pageText);
        GeminiIntegrationService.GeminiAnalysis analysis = service.analyzeWithGeminiDetails(domain, pageText);

        assertThat(riskScore).isZero();
        assertThat(analysis.scam()).isFalse();
    }
}
