package com.niscamke.backend.service;

import java.util.Locale;

import org.springframework.stereotype.Service;

@Service
public class GeminiIntegrationService {

    public boolean analyzeWithGemini(String domain, String pageText) {
        String normalizedDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);

        boolean targetsMalaysianBank = normalizedDomain.contains("bimb")
                || normalizedDomain.contains("cimb")
                || normalizedDomain.contains("maybank")
                || normalizedDomain.contains("secure");

        boolean trustedMalaysianDomain = normalizedDomain.endsWith(".com.my")
                || normalizedDomain.endsWith(".my");

        if (targetsMalaysianBank && !trustedMalaysianDomain) {
            return true;
        }

        /*
         * Day 2 Gemini integration handoff:
         *
         * Person 2 can add the live Google Gemini WebClient / REST call here.
         * Build a prompt using domain and pageText, call the Gemini API, parse
         * the response, and return true when Gemini classifies the link as a scam.
         */

        return false;
    }
}
