package com.scamlens.service;

import com.scamlens.dto.DashboardStatsDto;
import com.scamlens.dto.ScanResponse;
import com.scamlens.model.Scan;
import com.scamlens.model.User;
import com.scamlens.repository.ScanRepository;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class DashboardService {

    private final ScanRepository scanRepository;
    private final ScanService scanService;

    public DashboardService(ScanRepository scanRepository, ScanService scanService) {
        this.scanRepository = scanRepository;
        this.scanService = scanService;
    }

    /**
     * Aggregates real database statistics strictly for the authenticated user.
     */
    public DashboardStatsDto getUserDashboardStats(User user) {
        DashboardStatsDto stats = new DashboardStatsDto();

        long total = scanRepository.countByUser(user);
        stats.setTotalScans(total);

        long low = scanRepository.countByUserAndRiskLevel(user, RiskScoringService.LEVEL_LOW);
        long medium = scanRepository.countByUserAndRiskLevel(user, RiskScoringService.LEVEL_MEDIUM);
        long high = scanRepository.countByUserAndRiskLevel(user, RiskScoringService.LEVEL_HIGH);
        long critical = scanRepository.countByUserAndRiskLevel(user, RiskScoringService.LEVEL_CRITICAL);

        stats.setLowRiskScans(low);
        stats.setMediumRiskScans(medium);
        stats.setHighRiskScans(high);
        stats.setCriticalRiskScans(critical);

        Double avgScore = scanRepository.getAverageRiskScore(user);
        stats.setAverageRiskScore(avgScore != null ? Math.round(avgScore * 10.0) / 10.0 : 0.0);

        // Fetch recent scans (last 5)
        List<Scan> recent = scanRepository.findTop5ByUserOrderByCreatedAtDesc(user);
        List<ScanResponse> recentResponses = recent.stream()
                .map(scanService::toResponse)
                .collect(Collectors.toList());
        stats.setRecentScans(recentResponses);

        // Risk level distribution map for Chart.js
        Map<String, Long> riskDist = new LinkedHashMap<>();
        riskDist.put("Low", low);
        riskDist.put("Medium", medium);
        riskDist.put("High", high);
        riskDist.put("Critical", critical);
        stats.setRiskDistribution(riskDist);

        // Category breakdown from user's actual scan history
        List<Scan> allScans = scanRepository.findByUserOrderByCreatedAtDesc(user);
        Map<String, Long> catDist = new LinkedHashMap<>();
        for (Scan s : allScans) {
            if (s.getScamCategory() != null && !s.getScamCategory().trim().isEmpty()) {
                String raw = s.getScamCategory();
                String enPart = raw.contains("|") ? raw.split("\\|", 2)[0].trim() : raw.trim();
                String[] cats = enPart.split(",\\s*");
                for (String c : cats) {
                    if (!c.trim().isEmpty() && !c.equalsIgnoreCase("None")) {
                        catDist.put(c.trim(), catDist.getOrDefault(c.trim(), 0L) + 1);
                    }
                }
            }
        }
        stats.setCategoryDistribution(catDist);

        // Dynamic security insights based on user activity
        List<String> insights = new ArrayList<>();
        if (total == 0) {
            insights.add("Welcome to ScamLens! Start by scanning your first message or suspicious link in the Message Scanner.");
            insights.add("You can also explore the 12 pre-loaded examples in Demo Mode to see our detection engine in action.");
        } else {
            if (critical + high > 0) {
                insights.add("Alert: " + (critical + high) + " scan(s) in your history had High or Critical threat ratings. Ensure you have not clicked their links or entered OTPs.");
            }
            if (!catDist.isEmpty()) {
                String topCategory = catDist.entrySet().stream()
                        .max(Map.Entry.comparingByValue())
                        .map(Map.Entry::getKey)
                        .orElse("Phishing");
                insights.add("Most frequent scam type encountered: " + topCategory + ". Check out our Security Intelligence Center to learn how attackers craft these attacks.");
            }
            if (stats.getAverageRiskScore() < 25) {
                insights.add("Good digital hygiene! Your average risk profile is currently in the Low category.");
            } else if (stats.getAverageRiskScore() >= 50) {
                insights.add("Caution advised: Your overall threat exposure is elevated. Treat all incoming unknown communications with heightened vigilance.");
            }
            insights.add("Remember: legitimate banking and customer service teams will never ask for your passwords, OTP, or CVV over SMS or email.");
        }
        stats.setSecurityInsights(insights);

        return stats;
    }
}
