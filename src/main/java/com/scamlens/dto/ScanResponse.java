package com.scamlens.dto;

import com.scamlens.model.ContextEvaluation;
import com.scamlens.model.ScamIndicator;
import com.scamlens.model.ScoreBreakdown;
import com.scamlens.model.UrlFinding;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class ScanResponse {

    private Long id;
    private String originalMessage;
    private String sourceType;
    private int riskScore;
    private String riskLevel;
    private String detectedLanguage = "English";
    private String languageCode = "en";
    private List<String> categories = new ArrayList<>();
    private List<String> categoriesTa = new ArrayList<>();
    private List<ScamIndicator> indicators = new ArrayList<>();
    private List<String> suspiciousPhrases = new ArrayList<>();
    private List<String> explanations = new ArrayList<>();
    private List<String> explanationsTa = new ArrayList<>();
    private List<UrlFinding> urlFindings = new ArrayList<>();
    private List<String> recommendations = new ArrayList<>();
    private List<String> recommendationsTa = new ArrayList<>();
    private List<String> actionDirectives = new ArrayList<>();
    private List<String> credentialTargets = new ArrayList<>();
    private boolean warningContext;
    private ContextEvaluation contextEvaluation;
    private ScoreBreakdown scoreBreakdown;
    private LocalDateTime createdAt;

    public ScanResponse() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getOriginalMessage() {
        return originalMessage;
    }

    public void setOriginalMessage(String originalMessage) {
        this.originalMessage = originalMessage;
    }

    public String getSourceType() {
        return sourceType;
    }

    public void setSourceType(String sourceType) {
        this.sourceType = sourceType;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getDetectedLanguage() {
        return detectedLanguage;
    }

    public void setDetectedLanguage(String detectedLanguage) {
        this.detectedLanguage = detectedLanguage;
    }

    public String getLanguageCode() {
        return languageCode;
    }

    public void setLanguageCode(String languageCode) {
        this.languageCode = languageCode;
    }

    public List<String> getCategories() {
        return categories;
    }

    public void setCategories(List<String> categories) {
        this.categories = categories;
    }

    public List<String> getCategoriesTa() {
        return categoriesTa;
    }

    public void setCategoriesTa(List<String> categoriesTa) {
        this.categoriesTa = categoriesTa;
    }

    public String getScamCategory() {
        return (categories != null && !categories.isEmpty()) ? String.join(", ", categories) : "";
    }

    public void setScamCategory(String scamCategory) {
        if (scamCategory != null && !scamCategory.trim().isEmpty()) {
            this.categories = List.of(scamCategory.split(",\\s*"));
        }
    }

    public List<ScamIndicator> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<ScamIndicator> indicators) {
        this.indicators = indicators;
    }

    public List<String> getSuspiciousPhrases() {
        return suspiciousPhrases;
    }

    public void setSuspiciousPhrases(List<String> suspiciousPhrases) {
        this.suspiciousPhrases = suspiciousPhrases;
    }

    public List<String> getExplanations() {
        return explanations;
    }

    public void setExplanations(List<String> explanations) {
        this.explanations = explanations;
    }

    public List<String> getExplanationsTa() {
        return explanationsTa;
    }

    public void setExplanationsTa(List<String> explanationsTa) {
        this.explanationsTa = explanationsTa;
    }

    public List<UrlFinding> getUrlFindings() {
        return urlFindings;
    }

    public void setUrlFindings(List<UrlFinding> urlFindings) {
        this.urlFindings = urlFindings;
    }

    public List<String> getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(List<String> recommendations) {
        this.recommendations = recommendations;
    }

    public List<String> getRecommendationsTa() {
        return recommendationsTa;
    }

    public void setRecommendationsTa(List<String> recommendationsTa) {
        this.recommendationsTa = recommendationsTa;
    }

    public List<String> getActionDirectives() {
        return actionDirectives;
    }

    public void setActionDirectives(List<String> actionDirectives) {
        this.actionDirectives = actionDirectives;
    }

    public List<String> getCredentialTargets() {
        return credentialTargets;
    }

    public void setCredentialTargets(List<String> credentialTargets) {
        this.credentialTargets = credentialTargets;
    }

    public boolean isWarningContext() {
        return warningContext;
    }

    public void setWarningContext(boolean warningContext) {
        this.warningContext = warningContext;
    }

    public ContextEvaluation getContextEvaluation() {
        return contextEvaluation;
    }

    public void setContextEvaluation(ContextEvaluation contextEvaluation) {
        this.contextEvaluation = contextEvaluation;
    }

    public ScoreBreakdown getScoreBreakdown() {
        return scoreBreakdown;
    }

    public void setScoreBreakdown(ScoreBreakdown scoreBreakdown) {
        this.scoreBreakdown = scoreBreakdown;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
