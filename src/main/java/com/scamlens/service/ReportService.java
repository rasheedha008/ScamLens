package com.scamlens.service;

import com.lowagie.text.*;
import com.lowagie.text.Font;
import com.lowagie.text.pdf.*;
import com.lowagie.text.pdf.draw.LineSeparator;
import com.scamlens.dto.ScanResponse;
import com.scamlens.model.ContextEvaluation;
import com.scamlens.model.ScamIndicator;
import com.scamlens.model.ScoreBreakdown;
import com.scamlens.model.UrlFinding;
import org.springframework.stereotype.Service;

import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.time.format.DateTimeFormatter;

@Service
public class ReportService {

    private static final Color COLOR_PRIMARY = new Color(10, 25, 47);      // Navy #0a192f
    private static final Color COLOR_ACCENT = new Color(14, 116, 144);     // Cyan #0e7490
    private static final Color COLOR_CRITICAL = new Color(220, 38, 38);    // Red
    private static final Color COLOR_HIGH = new Color(234, 88, 12);        // Orange
    private static final Color COLOR_MEDIUM = new Color(202, 138, 4);      // Yellow/Amber
    private static final Color COLOR_LOW = new Color(22, 163, 74);         // Green
    private static final Color COLOR_BG_LIGHT = new Color(248, 250, 252);  // Slate 50
    private static final Color COLOR_TEXT_MUTED = new Color(100, 116, 139);// Slate 500

    public byte[] generatePdfReport(ScanResponse scan) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 36, 36, 36, 36);
        PdfWriter writer = PdfWriter.getInstance(document, out);

        document.open();

        // Fonts
        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, COLOR_PRIMARY);
        Font subtitleFont = FontFactory.getFont(FontFactory.HELVETICA, 9, COLOR_TEXT_MUTED);
        Font innovationBadgeFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8, COLOR_ACCENT);
        Font sectionHeaderFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 11, COLOR_PRIMARY);
        Font normalBold = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.BLACK);
        Font normalText = FontFactory.getFont(FontFactory.HELVETICA, 8, new Color(30, 41, 59));
        Font disclaimerFont = FontFactory.getFont(FontFactory.HELVETICA_OBLIQUE, 7, COLOR_TEXT_MUTED);

        // Header Table
        PdfPTable headerTable = new PdfPTable(2);
        headerTable.setWidthPercentage(100);
        headerTable.setWidths(new float[]{65f, 35f});

        PdfPCell leftCell = new PdfPCell();
        leftCell.setBorder(com.lowagie.text.Rectangle.NO_BORDER);
        leftCell.addElement(new Paragraph("SCAMLENS CYBERSECURITY PLATFORM", titleFont));
        leftCell.addElement(new Paragraph("Intelligent Scam Detection & Comprehensive Threat Analysis Report", subtitleFont));
        leftCell.addElement(new Paragraph("Tagline: Think Before You Click. Stay Ahead of Scams.", subtitleFont));
        leftCell.addElement(new Paragraph("INNOVATIONS: 1. Context-Aware Detection  |  2. Explainable Multi-Indicator Scoring  |  3. Integrated Platform", innovationBadgeFont));
        headerTable.addCell(leftCell);

        PdfPCell rightCell = new PdfPCell();
        rightCell.setBorder(com.lowagie.text.Rectangle.NO_BORDER);
        rightCell.setHorizontalAlignment(Element.ALIGN_RIGHT);

        Color badgeColor;
        switch (scan.getRiskLevel() != null ? scan.getRiskLevel() : "Low") {
            case "Critical": badgeColor = COLOR_CRITICAL; break;
            case "High": badgeColor = COLOR_HIGH; break;
            case "Medium": badgeColor = COLOR_MEDIUM; break;
            default: badgeColor = COLOR_LOW; break;
        }

        Font scoreFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 16, badgeColor);
        Paragraph scorePara = new Paragraph("RISK SCORE: " + scan.getRiskScore() + "/100", scoreFont);
        scorePara.setAlignment(Element.ALIGN_RIGHT);
        rightCell.addElement(scorePara);

        Font levelFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, badgeColor);
        Paragraph levelPara = new Paragraph("RISK LEVEL: " + (scan.getRiskLevel() != null ? scan.getRiskLevel().toUpperCase() : "LOW"), levelFont);
        levelPara.setAlignment(Element.ALIGN_RIGHT);
        rightCell.addElement(levelPara);

        headerTable.addCell(rightCell);
        document.add(headerTable);

        // Separator Line
        LineSeparator sep = new LineSeparator(1, 100, COLOR_ACCENT, Element.ALIGN_CENTER, -2);
        document.add(new Chunk(sep));
        document.add(new Paragraph(" "));

        // Metadata Table
        PdfPTable metaTable = new PdfPTable(4);
        metaTable.setWidthPercentage(100);
        metaTable.setWidths(new float[]{20f, 25f, 30f, 25f});

        addMetaCell(metaTable, "Scan Reference", scan.getId() != null ? "#" + scan.getId() : "DEMO", normalBold, normalText);
        addMetaCell(metaTable, "Communication Channel", scan.getSourceType() != null ? scan.getSourceType() : "SMS", normalBold, normalText);
        String catDisplay = (scan.getCategories() != null && !scan.getCategories().isEmpty()) ? String.join(", ", scan.getCategories()) : "None";
        addMetaCell(metaTable, "Identified Threat Category", catDisplay, normalBold, normalText);
        String dateStr = scan.getCreatedAt() != null ?
                scan.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")) : "Current Session";
        addMetaCell(metaTable, "Audit Timestamp", dateStr, normalBold, normalText);

        document.add(metaTable);
        document.add(new Paragraph(" "));

        // Section 1: Original Submitted Content
        document.add(new Paragraph("1. SUBMITTED CONTENT FOR ANALYSIS", sectionHeaderFont));
        PdfPTable messageTable = new PdfPTable(1);
        messageTable.setWidthPercentage(100);
        PdfPCell msgCell = new PdfPCell(new Phrase(scan.getOriginalMessage(), normalText));
        msgCell.setBackgroundColor(COLOR_BG_LIGHT);
        msgCell.setPadding(6);
        msgCell.setBorderColor(new Color(226, 232, 240));
        messageTable.addCell(msgCell);
        document.add(messageTable);
        document.add(new Paragraph(" "));

        // Section 2: Innovation 1 - Context-Aware Intent Evaluation
        document.add(new Paragraph("2. INNOVATION 1: CONTEXT-AWARE INTENT EVALUATION", sectionHeaderFont));
        ContextEvaluation ctx = scan.getContextEvaluation();
        PdfPTable ctxTable = new PdfPTable(2);
        ctxTable.setWidthPercentage(100);
        ctxTable.setWidths(new float[]{30f, 70f});

        if (ctx != null) {
            addTableRow(ctxTable, "Evaluated Intent Classification", normalBold);
            addTableRow(ctxTable, ctx.getIntentType() + (ctx.isWarningAdvisory() ? " [PROTECTIVE ADVISORY]" : " [ATTACK VECTOR]"), normalText);

            addTableRow(ctxTable, "Intent Semantic Rationale", normalBold);
            addTableRow(ctxTable, ctx.getIntentDescription(), normalText);

            addTableRow(ctxTable, "Negation Patterns Detected", normalBold);
            String negText = ctx.isNegationDetected() ? "Yes (" + String.join(", ", ctx.getNegationPhrases()) + ")" : "None Detected";
            addTableRow(ctxTable, negText, normalText);

            addTableRow(ctxTable, "Credential Harvesting Targets", normalBold);
            String credText = ctx.isRequestIntentDetected() ? String.join(", ", ctx.getRequestedCredentials()) : "None Requested";
            addTableRow(ctxTable, credText, normalText);

            addTableRow(ctxTable, "Suspicious Action Directives", normalBold);
            String actionsText = ctx.getSuspiciousActionsIdentified().isEmpty() ? "None Identified" : String.join("; ", ctx.getSuspiciousActionsIdentified());
            addTableRow(ctxTable, actionsText, normalText);
        } else {
            addTableRow(ctxTable, "Context Status", normalBold);
            addTableRow(ctxTable, scan.isWarningContext() ? "Legitimate Institutional Security Advisory" : "Standard Context Evaluation", normalText);
        }
        document.add(ctxTable);
        document.add(new Paragraph(" "));

        // Section 3: Innovation 2 - Explainable Multi-Indicator Risk Breakdown
        document.add(new Paragraph("3. INNOVATION 2: EXPLAINABLE MULTI-INDICATOR RISK ASSESSMENT", sectionHeaderFont));
        ScoreBreakdown sb = scan.getScoreBreakdown();

        if (sb != null && !sb.getContributions().isEmpty()) {
            PdfPTable indTable = new PdfPTable(4);
            indTable.setWidthPercentage(100);
            indTable.setWidths(new float[]{22f, 20f, 12f, 46f});

            addTableHeader(indTable, "Indicator / Threat", normalBold);
            addTableHeader(indTable, "Extracted Phrase", normalBold);
            addTableHeader(indTable, "Weight", normalBold);
            addTableHeader(indTable, "Cybersecurity Threat Rationale", normalBold);

            for (ScoreBreakdown.IndicatorContribution contrib : sb.getContributions()) {
                addTableRow(indTable, contrib.getName(), normalText);
                addTableRow(indTable, contrib.getMatchedPhrase(), normalText);
                addTableRow(indTable, "+" + contrib.getWeight() + " pts", normalText);
                addTableRow(indTable, contrib.getImpactExplanation(), normalText);
            }
            document.add(indTable);

            // Category caps and adjustments
            if (!sb.getCategoryCapsApplied().isEmpty() || sb.getContextAdjustment() != null) {
                com.lowagie.text.List capList = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED, 10);
                capList.setListSymbol("• ");
                if (sb.getContextAdjustment() != null) {
                    capList.add(new ListItem("Context Adjustment: " + sb.getContextAdjustment(), normalText));
                }
                for (String capNotice : sb.getCategoryCapsApplied()) {
                    capList.add(new ListItem("Category Cap Applied: " + capNotice, normalText));
                }
                document.add(capList);
            }
        } else if (scan.getIndicators() != null && !scan.getIndicators().isEmpty()) {
            PdfPTable indTable = new PdfPTable(3);
            indTable.setWidthPercentage(100);
            indTable.setWidths(new float[]{28f, 22f, 50f});

            addTableHeader(indTable, "Indicator / Threat", normalBold);
            addTableHeader(indTable, "Extracted Phrase", normalBold);
            addTableHeader(indTable, "Threat Explanation", normalBold);

            for (ScamIndicator ind : scan.getIndicators()) {
                addTableRow(indTable, ind.getName(), normalText);
                addTableRow(indTable, ind.getMatchedPhrase(), normalText);
                addTableRow(indTable, ind.getExplanation(), normalText);
            }
            document.add(indTable);
        } else {
            Paragraph noInd = new Paragraph("No malicious indicators or threat patterns detected.", normalText);
            document.add(noInd);
        }
        document.add(new Paragraph(" "));

        // Section 4: Passive URL Inspection Findings (Innovation 3)
        document.add(new Paragraph("4. INNOVATION 3: COMBINED MESSAGE & PASSIVE URL INSPECTION", sectionHeaderFont));
        if (scan.getUrlFindings() != null && !scan.getUrlFindings().isEmpty()) {
            PdfPTable urlTable = new PdfPTable(3);
            urlTable.setWidthPercentage(100);
            urlTable.setWidths(new float[]{38f, 18f, 44f});

            addTableHeader(urlTable, "Analyzed URL", normalBold);
            addTableHeader(urlTable, "Inspection Status", normalBold);
            addTableHeader(urlTable, "Identified Threat Characteristics", normalBold);

            for (UrlFinding uf : scan.getUrlFindings()) {
                addTableRow(urlTable, uf.getOriginalUrl(), normalText);
                String status = uf.isSuspicious() ? "SUSPICIOUS" : "LOW RISK";
                addTableRow(urlTable, status, normalText);
                String reasons = uf.getReasons().isEmpty() ? "No suspicious indicators identified" : String.join("; ", uf.getReasons());
                addTableRow(urlTable, reasons, normalText);
            }
            document.add(urlTable);
        } else {
            Paragraph noUrls = new Paragraph("No external URLs or IP links detected in the submitted content.", normalText);
            document.add(noUrls);
        }
        document.add(new Paragraph(" "));

        // Section 5: Recommended Safety Actions
        document.add(new Paragraph("5. RECOMMENDED CYBERSECURITY ACTIONS", sectionHeaderFont));
        com.lowagie.text.List recList = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED, 10);
        recList.setListSymbol("• ");
        for (String rec : scan.getRecommendations()) {
            recList.add(new ListItem(rec, normalText));
        }
        document.add(recList);
        document.add(new Paragraph(" "));

        // Heuristic Disclaimer
        document.add(new Chunk(sep));
        Paragraph disclaimer = new Paragraph(
                "DISCLAIMER: The ScamLens Risk Score is an algorithmic heuristic risk indicator designed to evaluate suspicious patterns and warning signs. It does not constitute a legal certification or mathematical certainty. A low score does not guarantee complete safety, and a high score does not conclusively prove criminal activity. Always verify critical requests independently through official channels.",
                disclaimerFont
        );
        document.add(disclaimer);

        document.close();
        return out.toByteArray();
    }

    private void addMetaCell(PdfPTable table, String label, String value, Font labelFont, Font valueFont) {
        PdfPCell cell = new PdfPCell();
        cell.setBackgroundColor(COLOR_BG_LIGHT);
        cell.setPadding(5);
        cell.setBorderColor(new Color(226, 232, 240));
        cell.addElement(new Paragraph(label, labelFont));
        cell.addElement(new Paragraph(value != null ? value : "N/A", valueFont));
        table.addCell(cell);
    }

    private void addTableHeader(PdfPTable table, String text, Font font) {
        PdfPCell cell = new PdfPCell(new Phrase(text, font));
        cell.setBackgroundColor(new Color(241, 245, 249));
        cell.setPadding(5);
        cell.setBorderColor(new Color(203, 213, 225));
        table.addCell(cell);
    }

    private void addTableRow(PdfPTable table, String text, Font font) {
        PdfPCell cell = new PdfPCell(new Phrase(text != null ? text : "", font));
        cell.setPadding(4);
        cell.setBorderColor(new Color(226, 232, 240));
        table.addCell(cell);
    }
}
