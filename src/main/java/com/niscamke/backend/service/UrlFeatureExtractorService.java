package com.niscamke.backend.service;

import java.net.IDN;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;

@Service
public class UrlFeatureExtractorService {

    private static final Pattern IPV4_HOST = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private static final Set<String> TRUSTED_DOMAINS = Set.of(
            "bankislam.com.my", "bimb.com.my", "beubankislam.com.my",
            "maybank2u.com.my", "maybank.com.my", "maybank.com",
            "cimbclicks.com.my", "cimb.com.my",
            "rhbbank.com.my", "pbebank.com", "publicbank.com.my",
            "hongleongbank.com.my", "ambank.com.my", "affinalways.com",
            "mybsn.com.my", "agrobank.com.my", "bnm.gov.my");

    private static final Set<String> SHORTENER_DOMAINS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
            "rebrand.ly", "s.id", "shorturl.at");

    private static final List<String> HIGH_RISK_TLDS = List.of(
            ".click", ".online", ".site", ".top", ".xyz", ".icu", ".test", ".live");

    private static final List<String> BANK_KEYWORDS = List.of(
            "maybank", "maybank2u", "cimb", "cimbclicks", "bankislam", "bimb",
            "rhb", "publicbank", "pbebank", "hongleong", "ambank", "affin",
            "bsn", "mybsn", "agrobank", "agro");

    private static final List<String> SUSPICIOUS_DOMAIN_TOKENS = List.of(
            "secure", "login", "verify", "verification", "update", "account",
            "suspended", "alert", "tac", "otp", "reset", "confirm", "security",
            "check", "helpdesk", "hold");

    private static final List<String> CREDENTIAL_KEYWORDS = List.of(
            "otp", "tac", "fpx", "password", "kata laluan", "pin", "login",
            "log masuk", "verify", "verification", "account suspended",
            "akaun digantung", "security check", "sms code", "card details",
            "banking details", "card information", "card pin", "phone verification",
            "identity card", "private banking details", "customer password",
            "one-time password");

    private static final List<String> MALAYSIAN_GOVERNMENT_KEYWORDS = List.of(
            "kwsp", "epf", "lhdn", "hasil", "mytax", "bpn", "str", "sumbangan",
            "mykad", "jpn", "mysejahtera", "jpj");

    private static final List<String> PARCEL_KEYWORDS = List.of(
            "poslaju", "gdex", "jnt", "j&t", "ninjavan", "parcel", "delivery",
            "customs", "kastam");

    private static final List<String> INVESTMENT_KEYWORDS = List.of(
            "pelaburan", "investment", "roi", "crypto", "forex", "dividend",
            "guaranteed profit", "pulangan");

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

        if (isTrustedDomain(domain)) {
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

        if (SHORTENER_DOMAINS.contains(domain)) {
            addRisk(breakdown, indicators, "urlShortener", 20, "URL shortener hides the final destination.");
        }

        boolean highRiskTld = HIGH_RISK_TLDS.stream().anyMatch(domain::endsWith);
        if (highRiskTld) {
            addRisk(breakdown, indicators, "highRiskTld", 15, "High-risk or demo phishing TLD detected.");
        }

        boolean bankKeyword = BANK_KEYWORDS.stream().anyMatch(fullText::contains);
        if (bankKeyword && !domain.endsWith(".com.my") && !domain.endsWith(".com")) {
            addRisk(breakdown, indicators, "bankKeywordWithoutOfficialDomain", 30, "Malaysian bank keyword appears outside an official banking domain.");
        }

        boolean suspiciousDomainToken = SUSPICIOUS_DOMAIN_TOKENS.stream().anyMatch(domain::contains);
        if (suspiciousDomainToken) {
            addRisk(breakdown, indicators, "suspiciousDomainToken", 10, "Domain uses phishing-style action words such as verify, update, TAC, OTP, or account alert.");
        }

        boolean credentialKeyword = CREDENTIAL_KEYWORDS.stream().anyMatch(fullText::contains);
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

        boolean governmentKeyword = MALAYSIAN_GOVERNMENT_KEYWORDS.stream().anyMatch(fullText::contains);
        if (governmentKeyword && credentialKeyword && !domain.endsWith(".gov.my")) {
            addRisk(breakdown, indicators, "malaysianGovernmentPattern", 18, "Malaysian government or aid keyword paired with sensitive-data collection.");
        } else if (governmentKeyword && !domain.endsWith(".gov.my")) {
            addRisk(breakdown, indicators, "malaysianGovernmentPattern", 10, "Malaysian government or aid keyword appears outside a government domain.");
        }

        int score = breakdown.values().stream().mapToInt(Integer::intValue).sum();
        score = Math.min(100, Math.max(0, score));

        String threatType = classifyThreatType(score, bankKeyword, governmentKeyword, fullText, credentialKeyword);
        if (indicators.isEmpty()) {
            indicators.add("No strong phishing indicators detected by structural analysis.");
        }

        return new UrlRiskAssessment(normalizedUrl, domain, score, threatType, indicators, breakdown);
    }

    public String extractDomainName(String url) {
        return parseUrl(normalizeUrl(url)).domain();
    }

    private String classifyThreatType(int score, boolean bankKeyword, boolean governmentKeyword, String fullText, boolean credentialKeyword) {
        if (score < 15) {
            return "SAFE";
        }
        if (bankKeyword) {
            return "BANKING_PHISHING";
        }
        if (governmentKeyword) {
            return "GOVERNMENT_IMPERSONATION";
        }
        if (PARCEL_KEYWORDS.stream().anyMatch(fullText::contains)) {
            return "PARCEL_SCAM";
        }
        if (INVESTMENT_KEYWORDS.stream().anyMatch(fullText::contains)) {
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

    private boolean isTrustedDomain(String domain) {
        return TRUSTED_DOMAINS.stream()
                .anyMatch(trustedDomain -> domain.equals(trustedDomain) || domain.endsWith("." + trustedDomain))
                || domain.endsWith(".gov.my")
                || domain.endsWith(".edu.my");
    }

    private boolean hasLookalikeBankTerm(String domain) {
        String simplifiedDomain = domain
                .replace('0', 'o')
                .replace('1', 'l')
                .replace('3', 'e')
                .replace('4', 'a')
                .replace('5', 's')
                .replaceAll("[^a-z0-9]", "");

        for (String bankKeyword : BANK_KEYWORDS) {
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
