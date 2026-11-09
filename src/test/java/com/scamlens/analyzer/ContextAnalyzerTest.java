package com.scamlens.analyzer;

import com.scamlens.model.ContextEvaluation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ContextAnalyzerTest {

    private ContextAnalyzer contextAnalyzer;

    @BeforeEach
    void setUp() {
        contextAnalyzer = new ContextAnalyzer();
    }

    @Test
    @DisplayName("Should identify educational safety warning (Message A scenario)")
    void testIsProtectiveWarningMessage() {
        String warningMsg = "State Bank Alert: Never share your OTP, password, or CVV with anyone. Bank will never ask for credentials.";
        assertTrue(contextAnalyzer.isProtectiveWarningMessage(warningMsg));

        String scamMsg = "Your account is locked. Share your OTP immediately to verify your account.";
        assertFalse(contextAnalyzer.isProtectiveWarningMessage(scamMsg));
    }

    @Test
    @DisplayName("Should detect negated keywords in safety sentences")
    void testIsKeywordNegated() {
        String sentenceA = "Under no circumstances should you ever share your OTP with unknown callers.";
        assertTrue(contextAnalyzer.isKeywordNegated(sentenceA, "otp"));

        String sentenceB = "Please enter your OTP to proceed with the transaction.";
        assertFalse(contextAnalyzer.isKeywordNegated(sentenceB, "otp"));
    }

    @Test
    @DisplayName("Should detect harvest request intent for credentials (Message B scenario)")
    void testHasActiveRequestIntent() {
        String harvestSentence = "Share your OTP immediately to avoid account suspension.";
        assertTrue(contextAnalyzer.hasActiveRequestIntent(harvestSentence, "otp"));

        String safeSentence = "Never share your OTP with anyone.";
        assertFalse(contextAnalyzer.hasActiveRequestIntent(safeSentence, "otp"));
    }

    @Test
    @DisplayName("Should identify urgent action demands")
    void testHasUrgentActionDemand() {
        String urgent = "Your account will be blocked within 24 hours if you do not comply immediately.";
        assertTrue(contextAnalyzer.hasUrgentActionDemand(urgent));

        String standard = "You can update your profile preferences whenever convenient.";
        assertFalse(contextAnalyzer.hasUrgentActionDemand(standard));
    }

    @Test
    @DisplayName("Innovation 1: Evaluate context differentiating legitimate warning vs active scam attack")
    void testEvaluateContext() {
        // 1. Legitimate Warning
        String warningText = "RBI Security Advisory: We will never contact you to ask for your OTP or netbanking password. Do not disclose details.";
        ContextEvaluation evalWarning = contextAnalyzer.evaluateContext(warningText);
        assertEquals(ContextAnalyzer.INTENT_LEGITIMATE_WARNING, evalWarning.getIntentType());
        assertTrue(evalWarning.isWarningAdvisory());
        assertTrue(evalWarning.isNegationDetected());
        assertFalse(evalWarning.isRequestIntentDetected());

        // 2. Active Attack
        String attackText = "URGENT: Your SBI account has been locked. Click here to verify and share your OTP immediately: http://fake.xyz";
        ContextEvaluation evalAttack = contextAnalyzer.evaluateContext(attackText);
        assertEquals(ContextAnalyzer.INTENT_ACTIVE_SCAM_REQUEST, evalAttack.getIntentType());
        assertFalse(evalAttack.isWarningAdvisory());
        assertTrue(evalAttack.isRequestIntentDetected());
        assertTrue(evalAttack.getRequestedCredentials().contains("OTP"));
        assertFalse(evalAttack.getSuspiciousActionsIdentified().isEmpty());

        // 3. Benign message
        String benignText = "Hello team, the weekly engineering synchronization meeting has been moved to Thursday at 3 PM.";
        ContextEvaluation evalBenign = contextAnalyzer.evaluateContext(benignText);
        assertEquals(ContextAnalyzer.INTENT_BENIGN_COMMUNICATION, evalBenign.getIntentType());
        assertFalse(evalBenign.isWarningAdvisory());
        assertFalse(evalBenign.isRequestIntentDetected());
    }

    @Test
    @DisplayName("Innovation 1: Identify suspicious action commands (link clicks, remote desktop, etc.)")
    void testIdentifySuspiciousActions() {
        String text = "Please download anydesk and call immediately at our customer care helpline to unblock.";
        List<String> actions = contextAnalyzer.identifySuspiciousActions(text);
        assertFalse(actions.isEmpty());
        assertTrue(actions.stream().anyMatch(a -> a.contains("Remote Desktop Access Command")));
        assertTrue(actions.stream().anyMatch(a -> a.contains("Immediate Direct Calling")));
    }
}
