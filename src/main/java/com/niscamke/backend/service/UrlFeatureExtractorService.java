package com.niscamke.backend.service;

import java.net.IDN;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UrlFeatureExtractorService {

    private static final Pattern IPV4_HOST = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private final ThreatIntelligenceService threatIntelligenceService;

    public UrlFeatureExtractorService() {
        this(new ThreatIntelligenceService());
    }

    @Autowired
    public UrlFeatureExtractorService(ThreatIntelligenceService threatIntelligenceService) {
        this.threatIntelligenceService = threatIntelligenceService;
    }

    public UrlRiskAssessment assess(String url, String pageText) {
        String normalizedUrl = normalizeUrl(url);
        ParsedUrl parsedUrl = parseUrl(normalizedUrl);
        String domain = parsedUrl.domain();
        String fullText = (normalizedUrl + " " + domain + " " + safe(pageText)).toLowerCase(Locale.ROOT);

        Map<String, Integer> breakdown = new LinkedHashMap<>();
        List<String> indicators = new ArrayList<>();

        if (domain.isBlank()) {
            addRisk(breakdown, indicators, "malformedUrl", 50, "URL could not be parsed safely.");
            return new UrlRiskAssessment(normalizedUrl, "", 50, "UNKNOWN", indicators, breakdown);
        }

        if (threatIntelligenceService.isTrustedDomain(domain)) {
            addRisk(breakdown, indicators, "trustedDomain", 0, "Recognised official Malaysian bank, government, or education domain.");
            return new UrlRiskAssessment(normalizedUrl, domain, 0, "SAFE", indicators, breakdown);
        }

        if ("http".equals(parsedUrl.scheme())) {
            addRisk(breakdown, indicators, "httpScheme", 12, "Uses plain HTTP instead of HTTPS.");
        }

        if (normalizedUrl.length() >= 180) {
            addRisk(breakdown, indicators, "urlLength", 15, "Very long URL often used to hide phishing paths.");
        } else if (normalizedUrl.length() >= 120) {
            addRisk(breakdown, indicators, "urlLength", 8, "Long URL deserves extra caution.");
        }

        int subdomainDepth = Math.max(0, domain.split("\\.").length - 2);
        if (subdomainDepth >= 4) {
            addRisk(breakdown, indicators, "subdomainDepth", 12, "Excessive subdomain nesting.");
        } else if (subdomainDepth >= 2) {
            addRisk(breakdown, indicators, "subdomainDepth", 6, "Multiple subdomains present.");
        }

        long hyphenCount = domain.chars().filter(ch -> ch == '-').count();
        if (hyphenCount >= 4) {
            addRisk(breakdown, indicators, "hyphenCount", 12, "Many hyphens in the domain.");
        } else if (hyphenCount >= 2) {
            addRisk(breakdown, indicators, "hyphenCount", 8, "Hyphenated domain resembles phishing naming.");
        }

        if (IPV4_HOST.matcher(domain).matches()) {
            addRisk(breakdown, indicators, "ipAddressHost", 25, "Uses an IP address instead of a normal domain.");
        }

        if (threatIntelligenceService.shortenerDomains().contains(domain)) {
            addRisk(breakdown, indicators, "urlShortener", 20, "URL shortener hides the final destination.");
        }

        boolean highRiskTld = threatIntelligenceService.highRiskTlds().stream().anyMatch(domain::endsWith);
        if (highRiskTld) {
            addRisk(breakdown, indicators, "highRiskTld", 15, "High-risk phishing TLD detected.");
        }

        boolean bankKeyword = threatIntelligenceService.containsAny(threatIntelligenceService.bankBrandTerms(), fullText);
        if (bankKeyword && !domain.endsWith(".com.my") && !domain.endsWith(".com")) {
            addRisk(breakdown, indicators, "bankKeywordWithoutOfficialDomain", 30, "Malaysian bank keyword appears outside an official banking domain.");
        }

        boolean suspiciousDomainToken = threatIntelligenceService.containsAny(threatIntelligenceService.suspiciousActionTerms(), domain);
        if (suspiciousDomainToken) {
            addRisk(breakdown, indicators, "suspiciousDomainToken", 10, "Domain uses phishing-style action words such as verify, update, TAC, OTP, or account alert.");
        }

        boolean credentialKeyword = threatIntelligenceService.containsAny(threatIntelligenceService.sensitiveCredentialTerms(), fullText);
        if (credentialKeyword) {
            addRisk(breakdown, indicators, "credentialKeywords", 25, "Requests login, OTP, TAC, FPX, password, or card details.");
        }

        if (bankKeyword && highRiskTld && (credentialKeyword || suspiciousDomainToken)) {
            addRisk(breakdown, indicators, "malaysianBankPhishingCombination", 17, "Bank brand, high-risk TLD, and credential/action wording appear together.");
        }

        if (domain.contains("xn--") || !domain.equals(toAsciiDomain(domain))) {
            addRisk(breakdown, indicators, "punycodeOrHomograph", 25, "Possible punycode or homograph domain.");
        }

        if (hasLookalikeBankTerm(domain)) {
            addRisk(breakdown, indicators, "bankLookalike", 25, "Domain is visually close to a Malaysian banking brand.");
        }

        if (parsedUrl.port() != -1 && !isStandardPort(parsedUrl.scheme(), parsedUrl.port())) {
            addRisk(breakdown, indicators, "nonStandardPort", 10, "Uses a non-standard web port.");
        }

        boolean governmentKeyword = threatIntelligenceService.containsAny(threatIntelligenceService.malaysianGovernmentTerms(), fullText);
        if (governmentKeyword && credentialKeyword && !domain.endsWith(".gov.my")) {
            addRisk(breakdown, indicators, "malaysianGovernmentPattern", 18, "Malaysian government or aid keyword paired with sensitive-data collection.");
        } else if (governmentKeyword && !domain.endsWith(".gov.my")) {
            addRisk(breakdown, indicators, "malaysianGovernmentPattern", 10, "Malaysian government or aid keyword appears outside a government domain.");
        }

        long applicationBaitMatches = threatIntelligenceService.countMatches(threatIntelligenceService.aidRewardBaitTerms(), fullText);
        boolean suspiciousApplicationRoute = threatIntelligenceService.containsAny(threatIntelligenceService.applicationRouteTerms(), fullText);
        if (applicationBaitMatches >= 2 && suspiciousApplicationRoute) {
            addRisk(breakdown, indicators, "aidOrRewardApplicationScam", 72, "Free aid or device bait appears with suspicious application-style routing.");
        } else if (applicationBaitMatches >= 2) {
            addRisk(breakdown, indicators, "aidOrRewardBait", 30, "Free aid, reward, or device bait detected.");
        }

        int score = breakdown.values().stream().mapToInt(Integer::intValue).sum();
        score = Math.min(100, Math.max(0, score));

        String threatType = classifyThreatType(score, bankKeyword, governmentKeyword, fullText, credentialKeyword, applicationBaitMatches);
        if (indicators.isEmpty()) {
            indicators.add("No strong phishing indicators detected by structural analysis.");
        }

        return new UrlRiskAssessment(normalizedUrl, domain, score, threatType, indicators, breakdown);
    }

    public String extractDomainName(String url) {
        return parseUrl(normalizeUrl(url)).domain();
    }

    private String classifyThreatType(int score, boolean bankKeyword, boolean governmentKeyword, String fullText, boolean credentialKeyword, long applicationBaitMatches) {
        if (score < 15) {
            return "SAFE";
        }
        if (bankKeyword) {
            return "BANKING_PHISHING";
        }
        if (applicationBaitMatches >= 2) {
            return "AID_OR_REWARD_SCAM";
        }
        if (governmentKeyword) {
            return "GOVERNMENT_IMPERSONATION";
        }
        if (threatIntelligenceService.containsAny(threatIntelligenceService.parcelTerms(), fullText)) {
            return "PARCEL_SCAM";
        }
        if (threatIntelligenceService.containsAny(threatIntelligenceService.investmentTerms(), fullText)) {
            return "INVESTMENT_SCAM";
        }
        if (credentialKeyword) {
            return "CREDENTIAL_HARVESTING";
        }
        return "UNKNOWN";
    }

    private void addRisk(Map<String, Integer> breakdown, List<String> indicators, String key, int score, String indicator) {
        breakdown.put(key, score);
        indicators.add(indicator);
    }

    private ParsedUrl parseUrl(String normalizedUrl) {
        try {
            URI uri = URI.create(normalizedUrl);
            String host = uri.getHost();
            if (host == null || host.isBlank()) {
                return new ParsedUrl("", "", -1);
            }

            String domain = host.toLowerCase(Locale.ROOT);
            if (domain.startsWith("www.")) {
                domain = domain.substring(4);
            }
            if (domain.endsWith(".")) {
                domain = domain.substring(0, domain.length() - 1);
            }
            return new ParsedUrl(uri.getScheme() == null ? "https" : uri.getScheme().toLowerCase(Locale.ROOT), domain, uri.getPort());
        } catch (IllegalArgumentException ex) {
            return new ParsedUrl("", "", -1);
        }
    }

    private String normalizeUrl(String url) {
        String trimmed = safe(url).trim();
        if (trimmed.isBlank()) {
            return "";
        }
        if (!trimmed.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) {
            return "https://" + trimmed;
        }
        return trimmed;
    }

    private boolean hasLookalikeBankTerm(String domain) {
        String simplifiedDomain = domain
                .replace('0', 'o')
                .replace('1', 'l')
                .replace('3', 'e')
                .replace('4', 'a')
                .replace('5', 's')
                .replaceAll("[^a-z0-9]", "");

        for (String bankKeyword : threatIntelligenceService.bankBrandTerms()) {
            String simplifiedKeyword = bankKeyword.replaceAll("[^a-z0-9]", "");
            if (simplifiedKeyword.length() <= 4) {
                continue;
            }
            if (!simplifiedDomain.contains(simplifiedKeyword)
                    && containsNearMatch(simplifiedDomain, simplifiedKeyword, 2)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsNearMatch(String text, String target, int threshold) {
        int targetLength = target.length();
        int minLength = Math.max(1, targetLength - threshold);
        int maxLength = Math.min(text.length(), targetLength + threshold);

        for (int length = minLength; length <= maxLength; length++) {
            for (int index = 0; index + length <= text.length(); index++) {
                String candidate = text.substring(index, index + length);
                if (levenshteinDistance(candidate, target) <= threshold) {
                    return true;
                }
            }
        }
        return false;
    }

    private int levenshteinDistance(String first, String second) {
        int[] previous = new int[second.length() + 1];
        int[] current = new int[second.length() + 1];

        for (int index = 0; index <= second.length(); index++) {
            previous[index] = index;
        }

        for (int firstIndex = 1; firstIndex <= first.length(); firstIndex++) {
            current[0] = firstIndex;
            for (int secondIndex = 1; secondIndex <= second.length(); secondIndex++) {
                int substitutionCost = first.charAt(firstIndex - 1) == second.charAt(secondIndex - 1) ? 0 : 1;
                current[secondIndex] = Math.min(
                        Math.min(current[secondIndex - 1] + 1, previous[secondIndex] + 1),
                        previous[secondIndex - 1] + substitutionCost);
            }
            int[] temp = previous;
            previous = current;
            current = temp;
        }
        return previous[second.length()];
    }

    private String toAsciiDomain(String domain) {
        try {
            return IDN.toASCII(domain);
        } catch (IllegalArgumentException ex) {
            return domain;
        }
    }

    private boolean isStandardPort(String scheme, int port) {
        return ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private record ParsedUrl(String scheme, String domain, int port) {
    }

    public record UrlRiskAssessment(
            String normalizedUrl,
            String domain,
            int score,
            String threatType,
            List<String> indicators,
            Map<String, Integer> scoreBreakdown) {
    }
}
