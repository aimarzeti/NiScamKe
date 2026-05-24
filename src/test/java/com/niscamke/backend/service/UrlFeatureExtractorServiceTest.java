package com.niscamke.backend.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class UrlFeatureExtractorServiceTest {

    private final UrlFeatureExtractorService service = new UrlFeatureExtractorService();

    @Test
    void flagsFakeAidFreeDeviceApplicationUrls() {
        UrlFeatureExtractorService.UrlRiskAssessment assessment = service.assess(
                "https://bantuanlaptop-percuma.apy-hy.com/ap1/",
                "");

        assertThat(assessment.score()).isGreaterThanOrEqualTo(80);
        assertThat(assessment.threatType()).isEqualTo("AID_OR_REWARD_SCAM");
        assertThat(assessment.scoreBreakdown()).containsKey("aidOrRewardApplicationScam");
    }

    @Test
    void stillAllowsTrustedOfficialBankDomain() {
        UrlFeatureExtractorService.UrlRiskAssessment assessment = service.assess(
                "https://www.maybank2u.com.my/",
                "Welcome to Maybank2u online banking.");

        assertThat(assessment.score()).isZero();
        assertThat(assessment.threatType()).isEqualTo("SAFE");
    }
}
