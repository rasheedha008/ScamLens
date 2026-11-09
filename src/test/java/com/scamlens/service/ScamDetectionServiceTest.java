package com.scamlens.service;

import com.scamlens.analyzer.ContextAnalyzer;
import com.scamlens.analyzer.MessageAnalyzer;
import com.scamlens.analyzer.ScamCategoryAnalyzer;
import com.scamlens.analyzer.UrlAnalyzer;
import com.scamlens.model.AnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ScamDetectionServiceTest {

    private ScamDetectionService detectionService;

    @BeforeEach
    void setUp() {
        MessageAnalyzer messageAnalyzer = new MessageAnalyzer();
        ContextAnalyzer contextAnalyzer = new ContextAnalyzer();
        UrlAnalyzer urlAnalyzer = new UrlAnalyzer();
        ScamCategoryAnalyzer categoryAnalyzer = new ScamCategoryAnalyzer(contextAnalyzer, messageAnalyzer);
        UrlAnalysisService urlAnalysisService = new UrlAnalysisService(urlAnalyzer);
        RiskScoringService riskScoringService = new RiskScoringService();
        RecommendationService recommendationService = new RecommendationService();

        detectionService = new ScamDetectionService(
                messageAnalyzer,
                contextAnalyzer,
                categoryAnalyzer,
                urlAnalysisService,
                riskScoringService,
                recommendationService
        );
    }

    @Test
    @DisplayName("Should handle empty message gracefully")
    void testEmptyMessage() {
        AnalysisResult result = detectionService.analyze("", "SMS");

        assertEquals(0, result.getRiskScore());
        assertEquals(RiskScoringService.LEVEL_LOW, result.getRiskLevel());
        assertFalse(result.getRecommendations().isEmpty());
    }

    @Test
    @DisplayName("Should handle normal everyday message with low risk score")
    void testNormalMessage() {
        String msg = "Hi Sarah, let's catch up for lunch at the cafeteria around 1 PM.";
        AnalysisResult result = detectionService.analyze(msg, "WhatsApp");

        assertEquals(0, result.getRiskScore());
        assertEquals(RiskScoringService.LEVEL_LOW, result.getRiskLevel());
    }

    @Test
    @DisplayName("Should evaluate security warning message (Message A) as low risk")
    void testProtectiveWarningMessage() {
        String msg = "Alert from State Bank: Never share your OTP, password, or CVV with anyone. Bank will never ask for credentials.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        assertTrue(result.isWarningContext());
        assertTrue(result.getRiskScore() <= 10);
        assertEquals(RiskScoringService.LEVEL_LOW, result.getRiskLevel());
        assertNotNull(result.getContextEvaluation());
        assertEquals("LEGITIMATE_WARNING", result.getContextEvaluation().getIntentType());
        assertNotNull(result.getScoreBreakdown());
        assertEquals(5, result.getScoreBreakdown().getFinalScore());
        assertTrue(result.getRecommendations().stream().anyMatch(r -> r.contains("legitimate fraud warning")));
    }

    @Test
    @DisplayName("Should evaluate active OTP harvest attack (Message B) as high or critical risk")
    void testActiveOtpHarvestAttack() {
        String msg = "Your card transaction of $850.00 is pending. Share your OTP immediately to verify your account or cancel: http://bank.auth-login.xyz/verify";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        assertFalse(result.isWarningContext());
        assertTrue(result.getRiskScore() >= 50);
        assertNotNull(result.getContextEvaluation());
        assertEquals("ACTIVE_SCAM_REQUEST", result.getContextEvaluation().getIntentType());
        assertNotNull(result.getScoreBreakdown());
        assertTrue(result.getScoreBreakdown().getFinalScore() >= 50);
        assertTrue(result.getCategories().contains("OTP and Credential Theft"));
        assertFalse(result.getUrlFindings().isEmpty());
        assertFalse(result.getRecommendations().isEmpty());
    }

    @Test
    @DisplayName("Should handle very long messages without crashing or exceeding limits")
    void testVeryLongMessage() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            sb.append("This is an extended text block for testing message length boundaries. ");
        }
        sb.append("Share your OTP immediately.");
        String longText = sb.toString();

        AnalysisResult result = detectionService.analyze(longText, "Email");
        assertNotNull(result);
        assertTrue(result.getOriginalMessage().length() <= 10000);
    }

    @Test
    @DisplayName("TC1: Should detect high/critical risk in bank phishing with OTP harvest")
    void testTC1_BankPhishingOtpTheft() {
        String msg = "URGENT: Your bank account will be suspended within 24 hours due to unauthorized login attempts. Share your OTP immediately to verify your identity and restore access at http://secure-bank-login.xyz";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("TC1 Score: " + result.getRiskScore() + ", Categories: " + result.getCategories());
        assertTrue(result.getRiskScore() >= 75, "Expected Critical Risk score >= 75, got: " + result.getRiskScore());
        assertTrue(result.getCategories().contains("OTP and Credential Theft"));
        assertTrue(result.getCategories().contains("Phishing"));
        assertTrue(result.getCategories().contains("Urgency and Threat Scams"));
        assertTrue(result.getCategories().contains("Suspicious URL"));
    }

    @Test
    @DisplayName("TC2: Should recognize legitimate security warning advisory with low risk")
    void testTC2_InstitutionalSecurityAdvisory() {
        String msg = "Security Advisory from State Bank: Never share your OTP, netbanking password, or UPI PIN with anyone over SMS or phone call. Bank officials will never ask for your confidential credentials.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("TC2 Score: " + result.getRiskScore() + ", Categories: " + result.getCategories());
        assertTrue(result.isWarningContext());
        assertEquals(5, result.getRiskScore());
        assertEquals(RiskScoringService.LEVEL_LOW, result.getRiskLevel());
        assertTrue(result.getCategories().contains("Legitimate Security Advisory"));
    }

    @Test
    @DisplayName("TC3: Should detect fake job scam with advance fee and task scam")
    void testTC3_FakeJobScamAdvanceFee() {
        String msg = "Congratulations! You have been selected for a part-time online job. Earn 5000 daily with simple YouTube like tasks from home. To activate your account, pay a refundable registration fee of 500 INR via UPI.";
        AnalysisResult result = detectionService.analyze(msg, "WhatsApp");

        System.out.println("TC3 Score: " + result.getRiskScore() + ", Categories: " + result.getCategories());
        assertTrue(result.getRiskScore() >= 50, "Expected High or Critical Risk score >= 50, got: " + result.getRiskScore());
        assertTrue(result.getCategories().contains("Fake Job Scams"));
        assertTrue(result.getCategories().contains("Financial Fraud"));
    }

    @Test
    @DisplayName("TC4: Should detect parcel delivery impersonation with suspicious URL")
    void testTC4_ParcelDeliveryPhish() {
        String msg = "Your package delivery is pending. Confirm your delivery address now: http://bit.ly/fedex-tracking-portal?token=8472948";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("TC4 Score: " + result.getRiskScore() + ", Categories: " + result.getCategories());
        assertTrue(result.getRiskScore() >= 50, "Expected High Risk score >= 50, got: " + result.getRiskScore());
        assertTrue(result.getCategories().contains("Impersonation"));
        assertTrue(result.getCategories().contains("Suspicious URL"));
    }

    @Test
    @DisplayName("TC5: Should detect normal everyday message as 0 risk")
    void testTC5_NormalMessage() {
        String msg = "Hi Alex, let's meet tomorrow at 3 PM at the coffee shop to review our project presentation slides. See you soon!";
        AnalysisResult result = detectionService.analyze(msg, "Email");

        System.out.println("TC5 Score: " + result.getRiskScore() + ", Categories: " + result.getCategories());
        assertEquals(0, result.getRiskScore());
        assertEquals(RiskScoringService.LEVEL_LOW, result.getRiskLevel());
        assertTrue(result.getCategories().isEmpty());
    }
}
