package com.scamlens.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DashboardStatsDto {

    private long totalScans;
    private long highRiskScans;
    private long criticalRiskScans;
    private long mediumRiskScans;
    private long lowRiskScans;
    private double averageRiskScore;
    private List<ScanResponse> recentScans = new ArrayList<>();
    private Map<String, Long> riskDistribution = new HashMap<>();
    private Map<String, Long> categoryDistribution = new HashMap<>();
    private List<String> securityInsights = new ArrayList<>();

    public DashboardStatsDto() {
    }

    public long getTotalScans() {
        return totalScans;
    }

    public void setTotalScans(long totalScans) {
        this.totalScans = totalScans;
    }

    public long getHighRiskScans() {
        return highRiskScans;
    }

    public void setHighRiskScans(long highRiskScans) {
        this.highRiskScans = highRiskScans;
    }

    public long getCriticalRiskScans() {
        return criticalRiskScans;
    }

    public void setCriticalRiskScans(long criticalRiskScans) {
        this.criticalRiskScans = criticalRiskScans;
    }

    public long getMediumRiskScans() {
        return mediumRiskScans;
    }

    public void setMediumRiskScans(long mediumRiskScans) {
        this.mediumRiskScans = mediumRiskScans;
    }

    public long getLowRiskScans() {
        return lowRiskScans;
    }

    public void setLowRiskScans(long lowRiskScans) {
        this.lowRiskScans = lowRiskScans;
    }

    public double getAverageRiskScore() {
        return averageRiskScore;
    }

    public void setAverageRiskScore(double averageRiskScore) {
        this.averageRiskScore = averageRiskScore;
    }

    public List<ScanResponse> getRecentScans() {
        return recentScans;
    }

    public void setRecentScans(List<ScanResponse> recentScans) {
        this.recentScans = recentScans;
    }

    public Map<String, Long> getRiskDistribution() {
        return riskDistribution;
    }

    public void setRiskDistribution(Map<String, Long> riskDistribution) {
        this.riskDistribution = riskDistribution;
    }

    public Map<String, Long> getCategoryDistribution() {
        return categoryDistribution;
    }

    public void setCategoryDistribution(Map<String, Long> categoryDistribution) {
        this.categoryDistribution = categoryDistribution;
    }

    public List<String> getSecurityInsights() {
        return securityInsights;
    }

    public void setSecurityInsights(List<String> securityInsights) {
        this.securityInsights = securityInsights;
    }
}
