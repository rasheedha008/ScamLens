package com.scamlens.model;

public class ScamIndicator {

    private String code;
    private String name;
    private String nameTa;
    private String category;
    private String categoryTa;
    private int weight;
    private String matchedPhrase;
    private String explanation;
    private String explanationTa;

    public ScamIndicator() {
    }

    public ScamIndicator(String code, String name, String category, int weight, String matchedPhrase, String explanation) {
        this.code = code;
        this.name = name;
        this.category = category;
        this.weight = weight;
        this.matchedPhrase = matchedPhrase;
        this.explanation = explanation;
    }

    public ScamIndicator(String code, String name, String nameTa, String category, String categoryTa, int weight, String matchedPhrase, String explanation, String explanationTa) {
        this.code = code;
        this.name = name;
        this.nameTa = nameTa;
        this.category = category;
        this.categoryTa = categoryTa;
        this.weight = weight;
        this.matchedPhrase = matchedPhrase;
        this.explanation = explanation;
        this.explanationTa = explanationTa;
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

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public String getExplanationTa() {
        return (explanationTa != null && !explanationTa.isEmpty()) ? explanationTa : explanation;
    }

    public void setExplanationTa(String explanationTa) {
        this.explanationTa = explanationTa;
    }
}
