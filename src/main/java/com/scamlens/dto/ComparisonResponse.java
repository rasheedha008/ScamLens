package com.scamlens.dto;

import java.util.ArrayList;
import java.util.List;

public class ComparisonResponse {

    private ScanResponse scanA;
    private ScanResponse scanB;
    private String higherRiskMessage; // "Message A", "Message B", or "Equal Risk"
    private int scoreDifference;
    private String riskLevelComparison;
    private List<String> mainDifferences = new ArrayList<>();
    private List<String> combinedRecommendations = new ArrayList<>();
    private String safetyNotice;

    public ComparisonResponse() {
    }

    public ScanResponse getScanA() {
        return scanA;
    }

    public void setScanA(ScanResponse scanA) {
        this.scanA = scanA;
    }

    public ScanResponse getScanB() {
        return scanB;
    }

    public void setScanB(ScanResponse scanB) {
        this.scanB = scanB;
    }

    public String getHigherRiskMessage() {
        return higherRiskMessage;
    }

    public void setHigherRiskMessage(String higherRiskMessage) {
        this.higherRiskMessage = higherRiskMessage;
    }

    public int getScoreDifference() {
        return scoreDifference;
    }

    public void setScoreDifference(int scoreDifference) {
        this.scoreDifference = scoreDifference;
    }

    public String getRiskLevelComparison() {
        return riskLevelComparison;
    }

    public void setRiskLevelComparison(String riskLevelComparison) {
        this.riskLevelComparison = riskLevelComparison;
    }

    public List<String> getMainDifferences() {
        return mainDifferences;
    }

    public void setMainDifferences(List<String> mainDifferences) {
        this.mainDifferences = mainDifferences;
    }

    public List<String> getCombinedRecommendations() {
        return combinedRecommendations;
    }

    public void setCombinedRecommendations(List<String> combinedRecommendations) {
        this.combinedRecommendations = combinedRecommendations;
    }

    public String getSafetyNotice() {
        return safetyNotice;
    }

    public void setSafetyNotice(String safetyNotice) {
        this.safetyNotice = safetyNotice;
    }
}
