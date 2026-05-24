package com.niscamke.backend.service;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import org.springframework.stereotype.Service;

@Service
public class ThreatIntelligenceService {

    private static final String RESOURCE_NAME = "threat-intelligence.properties";

    private final Properties properties;

    public ThreatIntelligenceService() {
        this.properties = loadProperties();
    }

    public List<String> trustedDomains() {
        return readList("trusted.domains");
    }

    public List<String> trustedSuffixes() {
        return readList("trusted.suffixes");
    }

    public List<String> shortenerDomains() {
        return readList("shortener.domains");
    }

    public List<String> highRiskTlds() {
        return readList("high-risk.tlds");
    }

    public List<String> bankBrandTerms() {
        return readList("bank.brand.terms");
    }

    public List<String> suspiciousActionTerms() {
        return readList("suspicious.action.terms");
    }

    public List<String> sensitiveCredentialTerms() {
        return readList("sensitive.credential.terms");
    }

    public List<String> malaysianGovernmentTerms() {
        return readList("malaysian.government.terms");
    }

    public List<String> parcelTerms() {
        return readList("parcel.terms");
    }

    public List<String> investmentTerms() {
        return readList("investment.terms");
    }

    public List<String> aidRewardBaitTerms() {
        return readList("aid-reward.bait.terms");
    }

    public List<String> applicationRouteTerms() {
        return readList("application.route.terms");
    }

    public boolean isTrustedDomain(String domain) {
        String normalizedDomain = normalize(domain);
        return trustedDomains().stream()
                .anyMatch(trustedDomain -> normalizedDomain.equals(trustedDomain) || normalizedDomain.endsWith("." + trustedDomain))
                || trustedSuffixes().stream().anyMatch(normalizedDomain::endsWith);
    }

    public boolean containsAny(List<String> terms, String text) {
        String normalizedText = normalize(text);
        return terms.stream().anyMatch(normalizedText::contains);
    }

    public long countMatches(List<String> terms, String text) {
        String normalizedText = normalize(text);
        return terms.stream().filter(normalizedText::contains).count();
    }

    private Properties loadProperties() {
        Properties loadedProperties = new Properties();
        try (InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(RESOURCE_NAME)) {
            if (stream == null) {
                throw new IllegalStateException("Missing " + RESOURCE_NAME + " on classpath.");
            }
            loadedProperties.load(stream);
            return loadedProperties;
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to load " + RESOURCE_NAME, ex);
        }
    }

    private List<String> readList(String key) {
        String rawValue = properties.getProperty(key, "");
        return java.util.Arrays.stream(rawValue.split(","))
                .map(this::normalize)
                .filter(value -> !value.isBlank())
                .distinct()
                .toList();
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
