package com.niscamke.backend.service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.niscamke.backend.repository.DecisionLogRepository;
import com.niscamke.backend.repository.FalsePositiveReportRepository;
import com.niscamke.backend.repository.ScamRegistryRepository;
import com.niscamke.backend.service.VerificationService.SummaryResponse;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ThreatAnalyticsService {

    private final DecisionLogRepository decisionLogRepository;
    private final ScamRegistryRepository scamRegistryRepository;
    private final FalsePositiveReportRepository falsePositiveReportRepository;
    private final GeminiIntegrationService geminiIntegrationService;
    private final VerificationService verificationService;

    public DashboardStatsResponse getDashboardStats() {
        return new DashboardStatsResponse(
                verificationService.getSummary(),
                getRecentThreats(),
                getSevenDayTrends(),
                getThreatTypeBreakdown(),
                getDetailedHealth());
    }

    public List<ThreatFeedItem> getRecentThreats() {
        return decisionLogRepository.findTop10ByDecisionOrderByCreatedAtDesc("BLOCK").stream()
                .map(log -> new ThreatFeedItem(
                        log.getDomainName(),
                        log.getRiskScore(),
                        valueOrUnknown(log.getThreatType()),
                        log.getReason(),
                        log.getCreatedAt() == null ? null : log.getCreatedAt().toString()))
                .toList();
    }

    public List<DailyTrendPoint> getSevenDayTrends() {
        LocalDate today = LocalDate.now();
        Map<LocalDate, long[]> counts = new LinkedHashMap<>();
        for (int dayOffset = 6; dayOffset >= 0; dayOffset--) {
            counts.put(today.minusDays(dayOffset), new long[3]);
        }

        decisionLogRepository.findAll().stream()
                .filter(log -> log.getCreatedAt() != null)
                .filter(log -> !log.getCreatedAt().toLocalDate().isBefore(today.minusDays(6)))
                .forEach(log -> {
                    long[] dayCounts = counts.get(log.getCreatedAt().toLocalDate());
                    if (dayCounts == null) {
                        return;
                    }
                    switch (log.getDecision()) {
                        case "ALLOW" -> dayCounts[0]++;
                        case "WARN" -> dayCounts[1]++;
                        case "BLOCK" -> dayCounts[2]++;
                        default -> {
                        }
                    }
                });

        return counts.entrySet().stream()
                .map(entry -> new DailyTrendPoint(
                        entry.getKey().toString(),
                        entry.getValue()[0],
                        entry.getValue()[1],
                        entry.getValue()[2]))
                .toList();
    }

    public List<ThreatTypeStat> getThreatTypeBreakdown() {
        Map<String, Long> counts = decisionLogRepository.findAll().stream()
                .filter(log -> "BLOCK".equals(log.getDecision()) || "WARN".equals(log.getDecision()))
                .collect(Collectors.groupingBy(log -> valueOrUnknown(log.getThreatType()), Collectors.counting()));

        List<ThreatTypeStat> stats = new ArrayList<>();
        counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder()))
                .forEach(entry -> stats.add(new ThreatTypeStat(entry.getKey(), entry.getValue())));
        return stats;
    }

    public DetailedHealthResponse getDetailedHealth() {
        SummaryResponse summary = verificationService.getSummary();
        long highThreatRegistryCount = scamRegistryRepository.countByThreatLevel("HIGH");
        return new DetailedHealthResponse(
                "UP",
                LocalDateTime.now().toString(),
                "NiScamKe Backend",
                geminiIntegrationService.isConfigured(),
                summary.totalScans(),
                summary.registryCount(),
                highThreatRegistryCount,
                summary.communityReportCount(),
                falsePositiveReportRepository.countByStatus("PENDING_REVIEW"),
                "H2 in-memory via Flyway");
    }

    private String valueOrUnknown(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value;
    }

    public record DashboardStatsResponse(
            SummaryResponse summary,
            List<ThreatFeedItem> recentThreats,
            List<DailyTrendPoint> trends,
            List<ThreatTypeStat> threatTypes,
            DetailedHealthResponse health) {
    }

    public record ThreatFeedItem(
            String domain,
            Integer riskScore,
            String threatType,
            String reason,
            String createdAt) {
    }

    public record DailyTrendPoint(
            String date,
            long allowCount,
            long warnCount,
            long blockCount) {
    }

    public record ThreatTypeStat(
            String threatType,
            long count) {
    }

    public record DetailedHealthResponse(
            String status,
            String timestamp,
            String service,
            boolean geminiConfigured,
            long totalScans,
            long registryCount,
            long highThreatRegistryCount,
            long communityReportCount,
            long pendingFalsePositiveReports,
            String database) {
    }
}
