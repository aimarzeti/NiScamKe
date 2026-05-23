package com.niscamke.backend.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class UrlFeatureExtractorServiceTest {

    private final UrlFeatureExtractorService service = new UrlFeatureExtractorService();

    @Test
    void trustsOfficialMalaysianFinancialDomains() {
        UrlFeatureExtractorService.UrlRiskAssessment assessment = service.assess(
                "https://www.maybank2u.com.my/",
                "Welcome to Maybank2u online banking.");

        assertThat(assessment.domain()).isEqualTo("maybank2u.com.my");
        assertThat(assessment.score()).isZero();
        assertThat(assessment.threatType()).isEqualTo("SAFE");
        assertThat(assessment.indicators()).contains("Recognised official Malaysian bank, government, or education domain.");
    }

    @Test
    void flagsSyntheticBankingPhishingBeforeAiIsNeeded() {
        UrlFeatureExtractorService.UrlRiskAssessment assessment = service.assess(
                "maybank-secure-login.test/verify-account?otp=required",
                "Verify your Maybank account password and OTP immediately.");

        assertThat(assessment.normalizedUrl()).startsWith("https://");
        assertThat(assessment.domain()).isEqualTo("maybank-secure-login.test");
        assertThat(assessment.score()).isGreaterThanOrEqualTo(80);
        assertThat(assessment.threatType()).isEqualTo("BANKING_PHISHING");
        assertThat(assessment.scoreBreakdown()).containsKeys(
                "highRiskTld",
                "bankKeywordWithoutOfficialDomain",
                "credentialKeywords",
                "malaysianBankPhishingCombination");
    }

    @Test
    void treatsGovernmentAidCredentialCollectionAsRisky() {
        UrlFeatureExtractorService.UrlRiskAssessment assessment = service.assess(
                "https://lhdn-refund.online/semakan",
                "Masukkan nombor MyKad, password, dan TAC untuk tuntut bayaran balik.");

        assertThat(assessment.score()).isGreaterThanOrEqualTo(45);
        assertThat(assessment.threatType()).isEqualTo("GOVERNMENT_IMPERSONATION");
        assertThat(assessment.scoreBreakdown()).containsKeys("highRiskTld", "credentialKeywords", "malaysianGovernmentPattern");
    }

    @Test
    void returnsWarnLevelAssessmentForMalformedUrls() {
        UrlFeatureExtractorService.UrlRiskAssessment assessment = service.assess("://not-a-url", "");

        assertThat(assessment.domain()).isBlank();
        assertThat(assessment.score()).isEqualTo(50);
        assertThat(assessment.threatType()).isEqualTo("UNKNOWN");
        assertThat(assessment.scoreBreakdown()).containsEntry("malformedUrl", 50);
    }
}
