package com.scamlens.service;

import com.scamlens.model.ContextEvaluation;
import com.scamlens.model.ScamIndicator;
import com.scamlens.model.ScoreBreakdown;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RiskScoringServiceTest {

    private RiskScoringService scoringService;

    @BeforeEach
    void setUp() {
        scoringService = new RiskScoringService();
    }

    @Test
    @DisplayName("Should reduce score to near-zero when warning context is true")
    void testWarningContextScore() {
        List<ScamIndicator> indicators = new ArrayList<>();
        indicators.add(new ScamIndicator("CRED_01", "OTP", "OTP and Credential Theft", 30, "otp", "Test"));

        int score = scoringService.calculateRiskScore(indicators, true, false);
        assertEquals(5, score);
        assertEquals(RiskScoringService.LEVEL_LOW, scoringService.determineRiskLevel(score));
    }

    @Test
    @DisplayName("Should calculate score correctly for single and multiple indicators")
    void testStandardCalculation() {
        List<ScamIndicator> indicators = new ArrayList<>();
        indicators.add(new ScamIndicator("CRED_01", "Sensitive Credential Request", "OTP and Credential Theft", 30, "share otp", "Test"));
        indicators.add(new ScamIndicator("PHISH_01", "Phishing Lure", "Phishing", 25, "verify account", "Test"));

        int score = scoringService.calculateRiskScore(indicators, false, false);
        assertEquals(55, score);
        assertEquals(RiskScoringService.LEVEL_HIGH, scoringService.determineRiskLevel(score));
    }

    @Test
    @DisplayName("Should prevent duplicate scoring for duplicate indicator codes")
    void testPreventDuplicateScoring() {
        List<ScamIndicator> indicators = new ArrayList<>();
        indicators.add(new ScamIndicator("CRED_01", "OTP Request", "OTP and Credential Theft", 30, "share otp", "Test"));
        indicators.add(new ScamIndicator("CRED_01", "OTP Request", "OTP and Credential Theft", 30, "share otp", "Test"));

        int score = scoringService.calculateRiskScore(indicators, false, false);
        assertEquals(30, score);
    }

    @Test
    @DisplayName("Should enforce category caps so single category cannot exceed maximum")
    void testCategoryCap() {
        List<ScamIndicator> indicators = new ArrayList<>();
        indicators.add(new ScamIndicator("CRED_01", "OTP", "OTP and Credential Theft", 30, "otp", "Test"));
        indicators.add(new ScamIndicator("CRED_02", "PIN", "OTP and Credential Theft", 30, "pin", "Test"));

        int score = scoringService.calculateRiskScore(indicators, false, false);
        // OTP category is capped at 40
        assertEquals(40, score);
        assertEquals(RiskScoringService.LEVEL_MEDIUM, scoringService.determineRiskLevel(score));
    }

    @Test
    @DisplayName("Should test all four risk level boundaries strictly")
    void testRiskLevelBoundaries() {
        assertEquals(RiskScoringService.LEVEL_LOW, scoringService.determineRiskLevel(0));
        assertEquals(RiskScoringService.LEVEL_LOW, scoringService.determineRiskLevel(24));

        assertEquals(RiskScoringService.LEVEL_MEDIUM, scoringService.determineRiskLevel(25));
        assertEquals(RiskScoringService.LEVEL_MEDIUM, scoringService.determineRiskLevel(49));

        assertEquals(RiskScoringService.LEVEL_HIGH, scoringService.determineRiskLevel(50));
        assertEquals(RiskScoringService.LEVEL_HIGH, scoringService.determineRiskLevel(74));

        assertEquals(RiskScoringService.LEVEL_CRITICAL, scoringService.determineRiskLevel(75));
        assertEquals(RiskScoringService.LEVEL_CRITICAL, scoringService.determineRiskLevel(100));
    }

    @Test
    @DisplayName("Should never exceed 100 even with extreme cumulative indicators")
    void testMaxScoreCapping() {
        List<ScamIndicator> indicators = new ArrayList<>();
        indicators.add(new ScamIndicator("CRED_01", "OTP", "OTP and Credential Theft", 30, "otp", "Test"));
        indicators.add(new ScamIndicator("FIN_01", "Money", "Financial Fraud", 25, "wire", "Test"));
        indicators.add(new ScamIndicator("JOB_01", "Job", "Fake Job Scams", 25, "fee", "Test"));
        indicators.add(new ScamIndicator("LOTTO_01", "Lotto", "Lottery and Prize Scams", 20, "won", "Test"));
        indicators.add(new ScamIndicator("URL_01", "URL", "Suspicious URL", 20, "http", "Test"));
        indicators.add(new ScamIndicator("IMP_01", "Imp", "Impersonation", 15, "dhl", "Test"));
        indicators.add(new ScamIndicator("URG_01", "Urg", "Urgency and Threat Scams", 10, "blocked", "Test"));

        int score = scoringService.calculateRiskScore(indicators, false, true);
        assertEquals(100, score);
        assertEquals(RiskScoringService.LEVEL_CRITICAL, scoringService.determineRiskLevel(score));
    }

    @Test
    @DisplayName("Innovation 2: Generate Explainable ScoreBreakdown with weights, caps, and rationale")
    void testGenerateScoreBreakdown() {
        List<ScamIndicator> indicators = new ArrayList<>();
        indicators.add(new ScamIndicator("CRED_01", "OTP Harvest", "OTP and Credential Theft", 30, "share otp", "Demanding secret one-time password"));
        indicators.add(new ScamIndicator("CRED_02", "PIN Harvest", "OTP and Credential Theft", 30, "atm pin", "Demanding ATM PIN"));
        indicators.add(new ScamIndicator("PHISH_01", "Phishing Lure", "Phishing", 25, "verify account", "Coercing login to deceptive portal"));

        ContextEvaluation attackContext = new ContextEvaluation();
        attackContext.setIntentType("ACTIVE_SCAM_REQUEST");
        attackContext.setWarningAdvisory(false);

        ScoreBreakdown breakdown = scoringService.generateScoreBreakdown(indicators, attackContext, true);

        assertNotNull(breakdown);
        assertEquals(90, breakdown.getRawTotalScore()); // 30 + 30 + 25 + 5 (urgency)
        // OTP category sum (60) is capped at 40. Phishing is 25. Urgency is 5. Total = 70.
        assertEquals(70, breakdown.getFinalScore());
        assertEquals(RiskScoringService.LEVEL_HIGH, breakdown.getRiskLevel());
        assertFalse(breakdown.getCategoryCapsApplied().isEmpty());
        assertTrue(breakdown.getCategoryCapsApplied().get(0).contains("OTP and Credential Theft capped at 40"));
        assertEquals(4, breakdown.getContributions().size());
        assertNotNull(breakdown.getLevelExplanation());
    }

    @Test
    @DisplayName("Innovation 2: Apply context negation discount in ScoreBreakdown for safety advisories")
    void testScoreBreakdownWarningDiscount() {
        List<ScamIndicator> indicators = new ArrayList<>();
        indicators.add(new ScamIndicator("CRED_01", "OTP", "OTP and Credential Theft", 30, "otp", "Mention of OTP"));

        ContextEvaluation warningContext = new ContextEvaluation();
        warningContext.setIntentType("LEGITIMATE_WARNING");
        warningContext.setWarningAdvisory(true);

        ScoreBreakdown breakdown = scoringService.generateScoreBreakdown(indicators, warningContext, false);

        assertEquals(5, breakdown.getFinalScore());
        assertEquals(RiskScoringService.LEVEL_LOW, breakdown.getRiskLevel());
        assertTrue(breakdown.getContextAdjustment().contains("Context-Aware Negation Discount"));
    }
}
