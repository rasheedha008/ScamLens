package com.scamlens.analyzer;

import com.scamlens.model.ScamIndicator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScamCategoryAnalyzerTest {

    private ScamCategoryAnalyzer categoryAnalyzer;

    @BeforeEach
    void setUp() {
        MessageAnalyzer messageAnalyzer = new MessageAnalyzer();
        ContextAnalyzer contextAnalyzer = new ContextAnalyzer();
        categoryAnalyzer = new ScamCategoryAnalyzer(contextAnalyzer, messageAnalyzer);
    }

    @Test
    @DisplayName("Should detect Phishing category")
    void testDetectPhishing() {
        String msg = "Your account has unusual activity. Click the link below to login and verify your account.";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(msg);

        assertTrue(indicators.stream().anyMatch(i -> i.getCategory().equals(ScamCategoryAnalyzer.CAT_PHISHING)));
    }

    @Test
    @DisplayName("Should detect OTP theft when harvest intent is present")
    void testDetectOtpTheft() {
        String msg = "A charge of $500 is pending. Share your OTP immediately to cancel.";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(msg);

        assertTrue(indicators.stream().anyMatch(i -> i.getCategory().equals(ScamCategoryAnalyzer.CAT_OTP_THEFT)));
    }

    @Test
    @DisplayName("Should NOT detect OTP theft when message is a safety warning")
    void testIgnoreNegatedOtpWarning() {
        String warningMsg = "State Bank Alert: Never share your OTP or password with anyone. Bank will never ask for credentials.";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(warningMsg);

        assertTrue(indicators.stream().noneMatch(i -> i.getCategory().equals(ScamCategoryAnalyzer.CAT_OTP_THEFT)));
    }

    @Test
    @DisplayName("Should detect Fake Job Scam with registration fee")
    void testDetectFakeJobScam() {
        String msg = "Part-time job offer! Work from home earn 5000/day. Pay registration fee for job now.";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(msg);

        assertTrue(indicators.stream().anyMatch(i -> i.getCategory().equals(ScamCategoryAnalyzer.CAT_FAKE_JOB)));
    }

    @Test
    @DisplayName("Should detect Lottery and Prize Scam")
    void testDetectLotteryScam() {
        String msg = "Congratulations you won! You have been selected as the lottery winner in our annual lucky draw.";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(msg);

        assertTrue(indicators.stream().anyMatch(i -> i.getCategory().equals(ScamCategoryAnalyzer.CAT_LOTTERY_SCAM)));
    }

    @Test
    @DisplayName("Should detect Financial Fraud and crypto doubler")
    void testDetectFinancialFraud() {
        String msg = "Crypto investment opportunity! Send money to double your money within 48 hours.";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(msg);

        assertTrue(indicators.stream().anyMatch(i -> i.getCategory().equals(ScamCategoryAnalyzer.CAT_FINANCIAL_FRAUD)));
    }

    @Test
    @DisplayName("Should detect Brand Impersonation")
    void testDetectImpersonation() {
        String msg = "Your parcel on hold with customs clearance fee due. Package delivery failed.";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(msg);

        assertTrue(indicators.stream().anyMatch(i -> i.getCategory().equals(ScamCategoryAnalyzer.CAT_IMPERSONATION)));
    }

    @Test
    @DisplayName("Should detect Urgency and Threat Scams")
    void testDetectUrgencyAndThreats() {
        String msg = "FINAL NOTICE: Your account will be blocked within 24 hours. Immediate action required!";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(msg);

        assertTrue(indicators.stream().anyMatch(i -> i.getCategory().equals(ScamCategoryAnalyzer.CAT_URGENCY_THREAT)));
    }

    @Test
    @DisplayName("Should detect multiple categories in compound attack message")
    void testMultipleCategoriesInCompoundMessage() {
        String compound = "Bank Alert: Your account will be blocked within 24 hours. Share your OTP immediately to verify your account.";
        List<ScamIndicator> indicators = categoryAnalyzer.detectIndicators(compound);

        long categoryCount = indicators.stream().map(ScamIndicator::getCategory).distinct().count();
        assertTrue(categoryCount >= 2);
    }
}
