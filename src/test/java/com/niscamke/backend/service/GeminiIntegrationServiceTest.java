package com.niscamke.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

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

    @Test
    void usesGeminiResponseWhenApiReturnsStructuredAnalysis() {
        RestTemplate restTemplate = new RestTemplate();
        GeminiIntegrationService serviceWithMockGemini = new GeminiIntegrationService(restTemplate, new ObjectMapper());
        ReflectionTestUtils.setField(serviceWithMockGemini, "apiKey", "test-key");
        MockRestServiceServer server = MockRestServiceServer.createServer(restTemplate);

        server.expect(requestTo("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=test-key"))
                .andRespond(withSuccess(geminiResponse("""
                        ```json
                        {"verdict":"SCAM","whyFlagged":"The page imitates a bank login and asks for OTP.","modusOperandi":"Victims are pushed to submit credentials on a fake portal."}
                        ```
                        """), MediaType.APPLICATION_JSON));

        GeminiIntegrationService.GeminiAnalysis analysis = serviceWithMockGemini.analyzeWithGeminiDetails(
                "maybank-secure-login.click",
                "Verify your account password and OTP now.");

        assertThat(analysis.scam()).isTrue();
        assertThat(analysis.reasons()).anySatisfy(reason -> assertThat(reason).contains("imitates a bank login"));
        server.verify();
    }

    @Test
    void retriesTransientGeminiFailureBeforeUsingSuccessfulResponse() {
        RestTemplate restTemplate = new RestTemplate();
        GeminiIntegrationService serviceWithMockGemini = new GeminiIntegrationService(restTemplate, new ObjectMapper());
        ReflectionTestUtils.setField(serviceWithMockGemini, "apiKey", "test-key");
        MockRestServiceServer server = MockRestServiceServer.createServer(restTemplate);

        String endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=test-key";
        server.expect(once(), requestTo(endpoint))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(once(), requestTo(endpoint))
                .andRespond(withSuccess(geminiResponse("""
                        {"verdict":"SAFE","whyFlagged":"No strong impersonation signals were found.","modusOperandi":"No scam workflow was visible."}
                        """), MediaType.APPLICATION_JSON));

        GeminiIntegrationService.GeminiAnalysis analysis = serviceWithMockGemini.analyzeWithGeminiDetails(
                "example.com",
                "Company profile and contact page.");

        assertThat(analysis.scam()).isFalse();
        assertThat(analysis.reasons()).anySatisfy(reason -> assertThat(reason).contains("No strong impersonation"));
        server.verify();
    }

    @Test
    void sendsRequestedLanguageToGeminiPrompt() {
        RestTemplate restTemplate = new RestTemplate();
        GeminiIntegrationService serviceWithMockGemini = new GeminiIntegrationService(restTemplate, new ObjectMapper());
        ReflectionTestUtils.setField(serviceWithMockGemini, "apiKey", "test-key");
        MockRestServiceServer server = MockRestServiceServer.createServer(restTemplate);

        server.expect(requestTo("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=test-key"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Bahasa Malaysia")))
                .andRespond(withSuccess(geminiResponse("""
                        {"verdict":"SCAM","whyFlagged":"Domain mencurigakan.","modusOperandi":"Mangsa diminta berkongsi OTP."}
                        """), MediaType.APPLICATION_JSON));

        GeminiIntegrationService.GeminiAnalysis analysis = serviceWithMockGemini.analyzeWithGeminiDetails(
                "cimb-tac-update.click",
                "Update TAC and OTP now.",
                "ms");

        assertThat(analysis.scam()).isTrue();
        server.verify();
    }

    private String geminiResponse(String text) {
        return """
                {
                  "candidates": [
                    {
                      "content": {
                        "parts": [
                          {
                            "text": %s
                          }
                        ]
                      }
                    }
                  ]
                }
                """.formatted(toJsonString(text));
    }

    private String toJsonString(String text) {
        try {
            return new ObjectMapper().writeValueAsString(text);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
