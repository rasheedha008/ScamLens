package com.scamlens.controller;

import com.scamlens.dto.ApiResponse;
import com.scamlens.dto.ScanResponse;
import com.scamlens.model.AnalysisResult;
import com.scamlens.service.DemoService;
import com.scamlens.service.ScamDetectionService;
import com.scamlens.service.ScanService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
public class DemoController {

    private final DemoService demoService;
    private final ScamDetectionService detectionService;
    private final ScanService scanService;

    public DemoController(DemoService demoService,
                          ScamDetectionService detectionService,
                          ScanService scanService) {
        this.demoService = demoService;
        this.detectionService = detectionService;
        this.scanService = scanService;
    }

    @GetMapping("/demo")
    public String demoPage(Authentication authentication, Model model) {
        boolean isAuthenticated = (authentication != null && authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getPrincipal()));
        model.addAttribute("isAuthenticated", isAuthenticated);
        model.addAttribute("samples", demoService.getAllSamples());
        return "demo";
    }

    @GetMapping("/api/demo/samples")
    @ResponseBody
    public ResponseEntity<ApiResponse<List<DemoService.DemoSample>>> getDemoSamples() {
        return ResponseEntity.ok(ApiResponse.ok(demoService.getAllSamples()));
    }

    @PostMapping("/api/demo/analyze/{id}")
    @ResponseBody
    public ResponseEntity<ApiResponse<ScanResponse>> runDemoAnalysis(@PathVariable("id") String id) {
        DemoService.DemoSample sample = demoService.getSampleById(id);
        if (sample == null) {
            return ResponseEntity.notFound().build();
        }

        // Process strictly through the real Java detection engine!
        AnalysisResult result = detectionService.analyze(sample.getContent(), sample.getSourceType());
        ScanResponse response = scanService.toResponse(result);

        return ResponseEntity.ok(ApiResponse.ok("Demo sample analyzed via Java engine", response));
    }
}
