package com.scamlens.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scans", indexes = {
    @Index(name = "idx_scan_user", columnList = "user_id"),
    @Index(name = "idx_scan_risk_level", columnList = "risk_level"),
    @Index(name = "idx_scan_created_at", columnList = "created_at")
})
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "original_message", nullable = false, columnDefinition = "LONGTEXT")
    private String originalMessage;

    @Column(name = "source_type", length = 50, nullable = false)
    private String sourceType;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "risk_level", length = 30, nullable = false)
    private String riskLevel;

    @Column(name = "scam_category", length = 500)
    private String scamCategory;

    @Column(name = "detected_language", length = 50)
    private String detectedLanguage = "English";

    @Column(name = "detected_indicators", columnDefinition = "LONGTEXT")
    private String detectedIndicators;

    @Column(name = "explanations", columnDefinition = "LONGTEXT")
    private String explanations;

    @Column(name = "url_findings", columnDefinition = "LONGTEXT")
    private String urlFindings;

    @Column(name = "recommendations", columnDefinition = "LONGTEXT")
    private String recommendations;

    @Column(name = "context_evaluation", columnDefinition = "LONGTEXT")
    private String contextEvaluation;

    @Column(name = "score_breakdown", columnDefinition = "LONGTEXT")
    private String scoreBreakdown;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    public Scan() {
    }

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
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

    public String getScamCategory() {
        return scamCategory;
    }

    public void setScamCategory(String scamCategory) {
        this.scamCategory = scamCategory;
    }

    public String getDetectedLanguage() {
        return detectedLanguage;
    }

    public void setDetectedLanguage(String detectedLanguage) {
        this.detectedLanguage = detectedLanguage;
    }

    public String getDetectedIndicators() {
        return detectedIndicators;
    }

    public void setDetectedIndicators(String detectedIndicators) {
        this.detectedIndicators = detectedIndicators;
    }

    public String getExplanations() {
        return explanations;
    }

    public void setExplanations(String explanations) {
        this.explanations = explanations;
    }

    public String getUrlFindings() {
        return urlFindings;
    }

    public void setUrlFindings(String urlFindings) {
        this.urlFindings = urlFindings;
    }

    public String getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(String recommendations) {
        this.recommendations = recommendations;
    }

    public String getContextEvaluation() {
        return contextEvaluation;
    }

    public void setContextEvaluation(String contextEvaluation) {
        this.contextEvaluation = contextEvaluation;
    }

    public String getScoreBreakdown() {
        return scoreBreakdown;
    }

    public void setScoreBreakdown(String scoreBreakdown) {
        this.scoreBreakdown = scoreBreakdown;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
