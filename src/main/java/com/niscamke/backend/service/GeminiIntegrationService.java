package com.niscamke.backend.service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * SCAMSHIELD AI - DEEP CORE REASONING ENGINE (PERSON 2)
 * Ganti fail tapak Person 1 dengan kod penuh API Gemini ini.
 */
@Service
public class GeminiIntegrationService {

    public boolean analyzeWithGemini(String domain, String pageText) {
        String normalizedDomain = domain == null ? "" : domain.toLowerCase(Locale.ROOT);

        // 1. Fast-Path Local Validation (Geng bank tiruan)
        boolean targetsMalaysianBank = normalizedDomain.contains("bimb")
                || normalizedDomain.contains("cimb")
                || normalizedDomain.contains("maybank")
                || normalizedDomain.contains("secure");

        boolean trustedMalaysianDomain = normalizedDomain.endsWith(".com.my")
                || normalizedDomain.endsWith(".my");

        if (targetsMalaysianBank && !trustedMalaysianDomain) {
            System.out.println("[ScamShield Fast-Path] Structural bank mimic detected. Hard-blocking threat.");
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

    public void connectToGemini() {
        String fullUrl = GEMINI_API_URL + apiKey;
    }
}
