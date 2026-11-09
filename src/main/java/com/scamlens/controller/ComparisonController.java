package com.scamlens.controller;

import com.scamlens.dto.ApiResponse;
import com.scamlens.dto.ComparisonRequest;
import com.scamlens.dto.ComparisonResponse;
import com.scamlens.dto.ScanResponse;
import com.scamlens.model.AnalysisResult;
import com.scamlens.service.ScamDetectionService;
import com.scamlens.service.ScanService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Controller
public class ComparisonController {

    private final ScamDetectionService detectionService;
    private final ScanService scanService;

    public ComparisonController(ScamDetectionService detectionService, ScanService scanService) {
        this.detectionService = detectionService;
        this.scanService = scanService;
    }

    @GetMapping("/compare")
    public String comparisonPage(Authentication authentication, Model model) {
        boolean isAuthenticated = (authentication != null && authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getPrincipal()));
        model.addAttribute("isAuthenticated", isAuthenticated);
        return "comparison";
    }

    @PostMapping("/api/compare")
    @ResponseBody
    public ResponseEntity<ApiResponse<ComparisonResponse>> compareMessages(@Valid @RequestBody ComparisonRequest request) {
        // 1. Analyze Message A
        AnalysisResult resA = detectionService.analyze(request.getMessageA(), request.getSourceTypeA());
        ScanResponse scanA = scanService.toResponse(resA);

        // 2. Analyze Message B
        AnalysisResult resB = detectionService.analyze(request.getMessageB(), request.getSourceTypeB());
        ScanResponse scanB = scanService.toResponse(resB);

        ComparisonResponse comparison = new ComparisonResponse();
        comparison.setScanA(scanA);
        comparison.setScanB(scanB);

        // 3. Score Comparison
        int diff = Math.abs(scanA.getRiskScore() - scanB.getRiskScore());
        comparison.setScoreDifference(diff);

        if (scanA.getRiskScore() > scanB.getRiskScore()) {
            comparison.setHigherRiskMessage("Message A");
            comparison.setRiskLevelComparison("Message A exhibits a higher risk profile (" + scanA.getRiskScore() +
                    " vs " + scanB.getRiskScore() + ").");
        } else if (scanB.getRiskScore() > scanA.getRiskScore()) {
            comparison.setHigherRiskMessage("Message B");
            comparison.setRiskLevelComparison("Message B exhibits a higher risk profile (" + scanB.getRiskScore() +
                    " vs " + scanA.getRiskScore() + ").");
        } else {
            comparison.setHigherRiskMessage("Equal Risk");
            comparison.setRiskLevelComparison("Both messages demonstrate equivalent risk scores (" + scanA.getRiskScore() + "/100).");
        }

        // 4. Main Differences
        List<String> differences = new ArrayList<>();
        differences.add("Message A Risk Classification: " + scanA.getRiskLevel() + " (" + scanA.getRiskScore() + "/100) vs " +
                "Message B: " + scanB.getRiskLevel() + " (" + scanB.getRiskScore() + "/100)");

        if (scanA.getContextEvaluation() != null && scanB.getContextEvaluation() != null) {
            String intentA = scanA.getContextEvaluation().getIntentType();
            String intentB = scanB.getContextEvaluation().getIntentType();
            if (!intentA.equals(intentB)) {
                differences.add("Semantic Intent Difference: Message A is evaluated as [" + intentA +
                        "] whereas Message B is evaluated as [" + intentB + "].");
            }
        }

        Set<String> catsA = new LinkedHashSet<>(scanA.getCategories());
        Set<String> catsB = new LinkedHashSet<>(scanB.getCategories());

        Set<String> onlyA = new LinkedHashSet<>(catsA);
        onlyA.removeAll(catsB);
        if (!onlyA.isEmpty()) {
            differences.add("Unique categories in Message A: " + String.join(", ", onlyA));
        }

        Set<String> onlyB = new LinkedHashSet<>(catsB);
        onlyB.removeAll(catsA);
        if (!onlyB.isEmpty()) {
            differences.add("Unique categories in Message B: " + String.join(", ", onlyB));
        }

        int urlsA = scanA.getUrlFindings() != null ? scanA.getUrlFindings().size() : 0;
        int urlsB = scanB.getUrlFindings() != null ? scanB.getUrlFindings().size() : 0;
        if (urlsA != urlsB) {
            differences.add("URL Density: Message A contains " + urlsA + " link(s), whereas Message B contains " + urlsB + " link(s).");
        }

        comparison.setMainDifferences(differences);

        // 5. Combined Recommendations
        Set<String> combinedRecs = new LinkedHashSet<>();
        combinedRecs.addAll(scanA.getRecommendations());
        combinedRecs.addAll(scanB.getRecommendations());
        comparison.setCombinedRecommendations(new ArrayList<>(combinedRecs));

        // 6. Safety notice: Do not automatically classify lower-scoring message as safe
        comparison.setSafetyNotice("CRITICAL ADVISORY: The message with the lower risk score is not automatically safe. Each message must be evaluated within its own operational context.");

        return ResponseEntity.ok(ApiResponse.ok("Comparison generated successfully", comparison));
    }
}
