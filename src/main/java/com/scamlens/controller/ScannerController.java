package com.scamlens.controller;

import com.scamlens.dto.ApiResponse;
import com.scamlens.dto.ScanRequest;
import com.scamlens.dto.ScanResponse;
import com.scamlens.model.AnalysisResult;
import com.scamlens.model.Scan;
import com.scamlens.model.User;
import com.scamlens.service.ScamDetectionService;
import com.scamlens.service.ScanService;
import com.scamlens.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class ScannerController {

    private final ScamDetectionService detectionService;
    private final ScanService scanService;
    private final UserService userService;

    public ScannerController(ScamDetectionService detectionService,
                             ScanService scanService,
                             UserService userService) {
        this.detectionService = detectionService;
        this.scanService = scanService;
        this.userService = userService;
    }

    @GetMapping("/scanner")
    public String scannerPage(@RequestParam(value = "demoId", required = false) String demoId,
                              Authentication authentication,
                              Model model) {
        boolean isAuthenticated = (authentication != null && authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getPrincipal()));
        model.addAttribute("isAuthenticated", isAuthenticated);
        model.addAttribute("demoId", demoId);
        return "scanner";
    }

    @PostMapping("/api/analyze")
    @ResponseBody
    public ResponseEntity<ApiResponse<ScanResponse>> analyzeMessage(@Valid @RequestBody ScanRequest request,
                                                                   Authentication authentication) {
        // 1. Execute Java Detection Engine
        AnalysisResult result = detectionService.analyze(request.getMessage(), request.getSourceType());

        // 2. Persist to user's history (to authenticated user, or primary user fallback so no scans are lost)
        ScanResponse response;
        boolean isAuthenticated = (authentication != null && authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getPrincipal()));

        User user = null;
        if (isAuthenticated) {
            user = userService.getUserByEmail(authentication.getName());
        }
        if (user == null) {
            user = userService.getDefaultUser();
        }

        if (user != null) {
            Scan savedScan = scanService.saveScan(result, user);
            response = scanService.toResponse(savedScan);
        } else {
            response = scanService.toResponse(result);
        }

        return ResponseEntity.ok(ApiResponse.ok("Analysis completed successfully", response));
    }

    @GetMapping("/result/{id}")
    public String viewResultPage(@PathVariable("id") Long id,
                                 Authentication authentication,
                                 Model model) {
        boolean isAuthenticated = (authentication != null && authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getPrincipal()));
        User user = null;
        if (isAuthenticated) {
            user = userService.getUserByEmail(authentication.getName());
        }
        if (user == null) {
            user = userService.getDefaultUser();
        }
        ScanResponse response = scanService.getScanResponseByIdAndUser(id, user);
        model.addAttribute("scan", response);
        model.addAttribute("user", user);
        return "result";
    }
}
