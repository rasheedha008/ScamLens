package com.scamlens.model;

import java.util.ArrayList;
import java.util.List;

public class ScoreBreakdown {

    public static class IndicatorContribution {
        private String code;
        private String name;
        private String nameTa;
        private String category;
        private String categoryTa;
        private int weight;
        private String matchedPhrase;
        private String impactExplanation;
        private String impactExplanationTa;

        public IndicatorContribution() {
        }

        public IndicatorContribution(String code, String name, String category, int weight, String matchedPhrase, String impactExplanation) {
            this.code = code;
            this.name = name;
            this.category = category;
            this.weight = weight;
            this.matchedPhrase = matchedPhrase;
            this.impactExplanation = impactExplanation;
        }

        public IndicatorContribution(String code, String name, String nameTa, String category, String categoryTa, int weight, String matchedPhrase, String impactExplanation, String impactExplanationTa) {
            this.code = code;
            this.name = name;
            this.nameTa = nameTa;
            this.category = category;
            this.categoryTa = categoryTa;
            this.weight = weight;
            this.matchedPhrase = matchedPhrase;
            this.impactExplanation = impactExplanation;
            this.impactExplanationTa = impactExplanationTa;
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getNameTa() {
            return (nameTa != null && !nameTa.isEmpty()) ? nameTa : name;
        }

        public void setNameTa(String nameTa) {
            this.nameTa = nameTa;
        }

        public String getCategory() {
            return category;
        }

        public void setCategory(String category) {
            this.category = category;
        }

        public String getCategoryTa() {
            return (categoryTa != null && !categoryTa.isEmpty()) ? categoryTa : category;
        }

        public void setCategoryTa(String categoryTa) {
            this.categoryTa = categoryTa;
        }

        public int getWeight() {
            return weight;
        }

        public void setWeight(int weight) {
            this.weight = weight;
        }

        public String getMatchedPhrase() {
            return matchedPhrase;
        }

        public void setMatchedPhrase(String matchedPhrase) {
            this.matchedPhrase = matchedPhrase;
        }

        public String getImpactExplanation() {
            return impactExplanation;
        }

        public void setImpactExplanation(String impactExplanation) {
            this.impactExplanation = impactExplanation;
        }

        public String getImpactExplanationTa() {
            return (impactExplanationTa != null && !impactExplanationTa.isEmpty()) ? impactExplanationTa : impactExplanation;
        }

        public void setImpactExplanationTa(String impactExplanationTa) {
            this.impactExplanationTa = impactExplanationTa;
        }
    }

    private int rawTotalScore;
    private int finalScore;
    private String riskLevel;
    private String levelExplanation;
    private String levelExplanationTa;
    private String contextAdjustment;
    private String contextAdjustmentTa;
    private List<IndicatorContribution> contributions = new ArrayList<>();
    private List<String> categoryCapsApplied = new ArrayList<>();
    private List<String> categoryCapsAppliedTa = new ArrayList<>();

    public ScoreBreakdown() {
    }

    public int getRawTotalScore() {
        return rawTotalScore;
    }

    public void setRawTotalScore(int rawTotalScore) {
        this.rawTotalScore = rawTotalScore;
    }

    public int getFinalScore() {
        return finalScore;
    }

    public void setFinalScore(int finalScore) {
        this.finalScore = finalScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getLevelExplanation() {
        return levelExplanation;
    }

    public void setLevelExplanation(String levelExplanation) {
        this.levelExplanation = levelExplanation;
    }

    public String getLevelExplanationTa() {
        return (levelExplanationTa != null && !levelExplanationTa.isEmpty()) ? levelExplanationTa : levelExplanation;
    }

    public void setLevelExplanationTa(String levelExplanationTa) {
        this.levelExplanationTa = levelExplanationTa;
    }

    public String getContextAdjustment() {
        return contextAdjustment;
    }

    public void setContextAdjustment(String contextAdjustment) {
        this.contextAdjustment = contextAdjustment;
    }

    public String getContextAdjustmentTa() {
        return (contextAdjustmentTa != null && !contextAdjustmentTa.isEmpty()) ? contextAdjustmentTa : contextAdjustment;
    }

    public void setContextAdjustmentTa(String contextAdjustmentTa) {
        this.contextAdjustmentTa = contextAdjustmentTa;
    }

    public List<IndicatorContribution> getContributions() {
        return contributions;
    }

    public void setContributions(List<IndicatorContribution> contributions) {
        this.contributions = contributions;
    }

    public List<String> getCategoryCapsApplied() {
        return categoryCapsApplied;
    }

    public void setCategoryCapsApplied(List<String> categoryCapsApplied) {
        this.categoryCapsApplied = categoryCapsApplied;
    }

    public List<String> getCategoryCapsAppliedTa() {
        return categoryCapsAppliedTa;
    }

    public void setCategoryCapsAppliedTa(List<String> categoryCapsAppliedTa) {
        this.categoryCapsAppliedTa = categoryCapsAppliedTa;
    }
}
