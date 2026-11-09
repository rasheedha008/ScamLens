package com.scamlens.service;

import com.scamlens.dto.ScanResponse;
import com.scamlens.model.ContextEvaluation;
import com.scamlens.model.ScamIndicator;
import com.scamlens.model.ScoreBreakdown;
import com.scamlens.model.UrlFinding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class ReportServiceTest {

    private ReportService reportService;

    @BeforeEach
    void setUp() {
        reportService = new ReportService();
    }

    @Test
    @DisplayName("Should generate valid PDF report bytes with OpenPDF")
    void testGeneratePdfReport() throws Exception {
        ScanResponse scan = new ScanResponse();
        scan.setId(101L);
        scan.setOriginalMessage("Dear user, please verify your account at http://login.bank.xyz immediately.");
        scan.setSourceType("SMS");
        scan.setRiskScore(65);
        scan.setRiskLevel("High");
        scan.setCategories(Arrays.asList("Phishing", "Suspicious URL"));
        scan.setCreatedAt(LocalDateTime.now());

        ScamIndicator ind = new ScamIndicator("PHISH_01", "Phishing Lure", "Phishing", 25, "verify your account", "Attempts credential harvesting.");
        scan.setIndicators(Collections.singletonList(ind));

        UrlFinding uf = new UrlFinding("http://login.bank.xyz");
        uf.setSuspicious(true);
        uf.addReason("Suspicious TLD .xyz");
        scan.setUrlFindings(Collections.singletonList(uf));

        ContextEvaluation ctx = new ContextEvaluation();
        ctx.setIntentType("ACTIVE_SCAM_REQUEST");
        ctx.setIntentDescription("Demands credential disclosure");
        ctx.setRequestIntentDetected(true);
        ctx.setRequestedCredentials(Collections.singletonList("OTP"));
        ctx.setSuspiciousActionsIdentified(Collections.singletonList("External Link Clicking"));
        scan.setContextEvaluation(ctx);

        ScoreBreakdown sb = new ScoreBreakdown();
        sb.setRawTotalScore(65);
        sb.setFinalScore(65);
        sb.setRiskLevel("High");
        sb.setLevelExplanation("High risk threat detected");
        sb.setContributions(Collections.singletonList(
                new ScoreBreakdown.IndicatorContribution("PHISH_01", "Phishing Lure", "Phishing", 25, "verify your account", "Attempts credential harvesting.")
        ));
        scan.setScoreBreakdown(sb);

        scan.setRecommendations(Arrays.asList("Do not click links", "Verify independently"));

        byte[] pdfBytes = reportService.generatePdfReport(scan);

        assertNotNull(pdfBytes);
        assertTrue(pdfBytes.length > 500);

        // Verify standard PDF magic header bytes: %PDF-
        String header = new String(pdfBytes, 0, 5);
        assertEquals("%PDF-", header);
    }
}
