package com.scamlens.model;

import java.util.ArrayList;
import java.util.List;

public class ContextEvaluation {

    private String intentType; // LEGITIMATE_WARNING, ACTIVE_SCAM_REQUEST, SUSPICIOUS_DEMAND, BENIGN_COMMUNICATION
    private String intentTypeTa;
    private String intentDescription;
    private String intentDescriptionTa;
    private boolean negationDetected;
    private List<String> negationPhrases = new ArrayList<>();
    private boolean requestIntentDetected;
    private List<String> requestedCredentials = new ArrayList<>();
    private List<String> suspiciousActionsIdentified = new ArrayList<>();
    private List<String> actionDirectives = new ArrayList<>();
    private List<String> credentialTargets = new ArrayList<>();
    private boolean isWarningAdvisory;

    public ContextEvaluation() {
    }

    public String getIntentType() {
        return intentType;
    }

    public void setIntentType(String intentType) {
        this.intentType = intentType;
    }

    public String getIntentTypeTa() {
        return (intentTypeTa != null && !intentTypeTa.isEmpty()) ? intentTypeTa : intentType;
    }

    public void setIntentTypeTa(String intentTypeTa) {
        this.intentTypeTa = intentTypeTa;
    }

    public String getIntentDescription() {
        return intentDescription;
    }

    public void setIntentDescription(String intentDescription) {
        this.intentDescription = intentDescription;
    }

    public String getIntentDescriptionTa() {
        return (intentDescriptionTa != null && !intentDescriptionTa.isEmpty()) ? intentDescriptionTa : intentDescription;
    }

    public void setIntentDescriptionTa(String intentDescriptionTa) {
        this.intentDescriptionTa = intentDescriptionTa;
    }

    public boolean isNegationDetected() {
        return negationDetected;
    }

    public void setNegationDetected(boolean negationDetected) {
        this.negationDetected = negationDetected;
    }

    public List<String> getNegationPhrases() {
        return negationPhrases;
    }

    public void setNegationPhrases(List<String> negationPhrases) {
        this.negationPhrases = negationPhrases;
    }

    public boolean isRequestIntentDetected() {
        return requestIntentDetected;
    }

    public void setRequestIntentDetected(boolean requestIntentDetected) {
        this.requestIntentDetected = requestIntentDetected;
    }

    public List<String> getRequestedCredentials() {
        return requestedCredentials;
    }

    public void setRequestedCredentials(List<String> requestedCredentials) {
        this.requestedCredentials = requestedCredentials;
    }

    public List<String> getSuspiciousActionsIdentified() {
        return suspiciousActionsIdentified;
    }

    public void setSuspiciousActionsIdentified(List<String> suspiciousActionsIdentified) {
        this.suspiciousActionsIdentified = suspiciousActionsIdentified;
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

    public boolean isWarningAdvisory() {
        return isWarningAdvisory;
    }

    public void setWarningAdvisory(boolean warningAdvisory) {
        isWarningAdvisory = warningAdvisory;
    }
}
