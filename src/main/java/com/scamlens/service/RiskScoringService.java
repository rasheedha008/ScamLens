package com.scamlens.service;

import com.scamlens.model.ContextEvaluation;
import com.scamlens.model.ScamIndicator;
import com.scamlens.model.ScoreBreakdown;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Innovation 2: Explainable Multi-Indicator Risk Assessment Engine.
 * Evaluates multiple suspicious indicators using a weighted risk-scoring mechanism,
 * enforces category caps, generates a 0-100 risk score, and provides transparent explanations
 * for detected threats, suspicious phrases, and assigned risk levels.
 */
@Service
public class RiskScoringService {

    public static final String LEVEL_LOW = "Low";
    public static final String LEVEL_MEDIUM = "Medium";
    public static final String LEVEL_HIGH = "High";
    public static final String LEVEL_CRITICAL = "Critical";

    // Category caps to avoid excessive duplicate accumulation in a single category
    private static final Map<String, Integer> CATEGORY_CAPS = new HashMap<>();
    static {
        CATEGORY_CAPS.put("Phishing", 35);
        CATEGORY_CAPS.put("OTP and Credential Theft", 40);
        CATEGORY_CAPS.put("Financial Fraud", 35);
        CATEGORY_CAPS.put("Lottery and Prize Scams", 30);
        CATEGORY_CAPS.put("Fake Job Scams", 35);
        CATEGORY_CAPS.put("Impersonation", 25);
        CATEGORY_CAPS.put("Urgency and Threat Scams", 20);
        CATEGORY_CAPS.put("Suspicious URL", 35);
    }

    /**
     * Calculates the aggregate risk score between 0 and 100.
     */
    public int calculateRiskScore(List<ScamIndicator> indicators, boolean isWarningContext, boolean hasExcessiveUrgency) {
        if (isWarningContext) {
            // Safety warnings (e.g. "Never share your OTP with anyone") have near-zero risk
            return 5;
        }

        if (indicators == null || indicators.isEmpty()) {
            return hasExcessiveUrgency ? 15 : 0;
        }

        // Group indicators by category to apply category caps and prevent double counting
        Map<String, Integer> categoryScores = new HashMap<>();
        Set<String> seenCodes = new HashSet<>();

        for (ScamIndicator ind : indicators) {
            if (seenCodes.contains(ind.getCode() + "_" + ind.getMatchedPhrase())) {
                continue;
            }
            seenCodes.add(ind.getCode() + "_" + ind.getMatchedPhrase());

            String category = ind.getCategory();
            int currentCatScore = categoryScores.getOrDefault(category, 0);
            categoryScores.put(category, currentCatScore + ind.getWeight());
        }

        int totalAccumulatedScore = 0;
        for (Map.Entry<String, Integer> entry : categoryScores.entrySet()) {
            String cat = entry.getKey();
            int score = entry.getValue();
            int cap = CATEGORY_CAPS.getOrDefault(cat, 35);
            totalAccumulatedScore += Math.min(score, cap);
        }

        if (hasExcessiveUrgency) {
            totalAccumulatedScore += 5;
        }

        // Bounded strictly between 0 and 100
        return Math.max(0, Math.min(100, totalAccumulatedScore));
    }

    /**
     * Generates a fully explainable risk score breakdown detailing
     * raw contributions, applied category caps, context adjustments, and risk rationale.
     */
    public ScoreBreakdown generateScoreBreakdown(List<ScamIndicator> indicators,
                                                 ContextEvaluation contextEval,
                                                 boolean hasExcessiveUrgency) {
        ScoreBreakdown breakdown = new ScoreBreakdown();
        boolean isWarning = contextEval != null && contextEval.isWarningAdvisory();

        int rawTotal = 0;
        Map<String, Integer> categorySums = new LinkedHashMap<>();
        List<ScoreBreakdown.IndicatorContribution> contributions = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        if (indicators != null) {
            for (ScamIndicator ind : indicators) {
                String dedupKey = ind.getCode() + "_" + ind.getMatchedPhrase();
                if (seen.contains(dedupKey)) {
                    continue;
                }
                seen.add(dedupKey);

                rawTotal += ind.getWeight();
                categorySums.put(ind.getCategory(), categorySums.getOrDefault(ind.getCategory(), 0) + ind.getWeight());

                contributions.add(new ScoreBreakdown.IndicatorContribution(
                        ind.getCode(),
                        ind.getName(),
                        ind.getCategory(),
                        ind.getWeight(),
                        ind.getMatchedPhrase(),
                        ind.getExplanation()
                ));
            }
        }

        if (hasExcessiveUrgency) {
            rawTotal += 5;
            contributions.add(new ScoreBreakdown.IndicatorContribution(
                    "STRUCTURAL_URGENCY",
                    "Excessive Punctuation & Capitalization",
                    "Urgency and Threat Scams",
                    5,
                    "UPPERCASE / !!?",
                    "Formatting signals artificial panic induction to bypass critical thinking."
            ));
        }

        breakdown.setRawTotalScore(rawTotal);
        breakdown.setContributions(contributions);

        // Apply Category Caps
        List<String> capsApplied = new ArrayList<>();
        int cappedScore = 0;
        for (Map.Entry<String, Integer> entry : categorySums.entrySet()) {
            String cat = entry.getKey();
            int sum = entry.getValue();
            int maxCap = CATEGORY_CAPS.getOrDefault(cat, 35);
            if (sum > maxCap) {
                capsApplied.add(cat + " capped at " + maxCap + " points (raw accumulated: " + sum + ")");
                cappedScore += maxCap;
            } else {
                cappedScore += sum;
            }
        }
        if (hasExcessiveUrgency) {
            cappedScore += 5;
        }
        breakdown.setCategoryCapsApplied(capsApplied);

        // Context Adjustment
        int finalScore;
        if (isWarning) {
            finalScore = 5;
            breakdown.setContextAdjustment("Context-Aware Negation Discount: Legitimate security advisory identified. Threat weights reduced to baseline benign score (5/100).");
        } else {
            finalScore = Math.max(0, Math.min(100, cappedScore));
            if (contextEval != null && "ACTIVE_SCAM_REQUEST".equals(contextEval.getIntentType())) {
                breakdown.setContextAdjustment("Active Credential Harvest / Direct Command verified: Full threat weights enforced.");
            } else if (contextEval != null && "SUSPICIOUS_DEMAND".equals(contextEval.getIntentType())) {
                breakdown.setContextAdjustment("Suspicious Coercive Demand detected: Threat weights applied without negation discount.");
            } else {
                breakdown.setContextAdjustment("Standard rule-based multi-indicator evaluation.");
            }
        }

        breakdown.setFinalScore(finalScore);
        String level = determineRiskLevel(finalScore);
        breakdown.setRiskLevel(level);
        breakdown.setLevelExplanation(getRiskLevelExplanation(level, finalScore, isWarning));

        return breakdown;
    }

    /**
     * Explains the risk level assignment based on cybersecurity threat modeling.
     */
    public String getRiskLevelExplanation(String level, int score, boolean isWarning) {
        if (isWarning) {
            return "Low Risk (Score " + score + "/100): The message is an educational alert or institutional security advisory cautioning recipients against disclosing credentials.";
        }
        switch (level) {
            case LEVEL_CRITICAL:
                return "Critical Risk (Score " + score + "/100): High-confidence malicious attack detected. Multiple compounding threat indicators present (credential harvesting, impersonation, or weaponized URLs). Immediate danger of fraud.";
            case LEVEL_HIGH:
                return "High Risk (Score " + score + "/100): Strong indicators of deception identified, including coercive language, suspicious links, or unauthorized requests for confidential actions.";
            case LEVEL_MEDIUM:
                return "Medium Risk (Score " + score + "/100): Caution recommended. Contains suspicious elements such as urgency cues, unverified contact requests, or promotional lottery claims.";
            default:
                return "Low Risk (Score " + score + "/100): Minimal or no threat patterns detected. Content appears benign, informational, or verified.";
        }
    }

    /**
     * Determines risk classification level.
     */
    public String determineRiskLevel(int score) {
        if (score >= 75) {
            return LEVEL_CRITICAL;
        } else if (score >= 50) {
            return LEVEL_HIGH;
        } else if (score >= 25) {
            return LEVEL_MEDIUM;
        } else {
            return LEVEL_LOW;
        }
    }
}
