package com.scamlens.controller;

import com.scamlens.dto.ApiResponse;
import com.scamlens.dto.ScanResponse;
import com.scamlens.model.User;
import com.scamlens.service.ScanService;
import com.scamlens.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
public class HistoryController {

    private final ScanService scanService;
    private final UserService userService;

    public HistoryController(ScanService scanService, UserService userService) {
        this.scanService = scanService;
        this.userService = userService;
    }

    @GetMapping("/history")
    public String historyPage(Authentication authentication, Model model) {
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            return "redirect:/login";
        }
        User user = userService.getUserByEmail(authentication.getName());
        List<ScanResponse> scans = scanService.getUserScans(user);
        model.addAttribute("scans", scans);
        model.addAttribute("user", user);
        return "history";
    }

    @GetMapping("/api/history")
    @ResponseBody
    public ResponseEntity<ApiResponse<List<ScanResponse>>> getHistory(
            @RequestParam(value = "riskLevel", required = false) String riskLevel,
            @RequestParam(value = "category", required = false) String category,
            @RequestParam(value = "keyword", required = false) String keyword,
            Authentication authentication) {
        User user = userService.getUserByEmail(authentication.getName());
        List<ScanResponse> scans = scanService.searchUserScans(user, riskLevel, category, keyword);
        return ResponseEntity.ok(ApiResponse.ok(scans));
    }

    @GetMapping("/api/history/{id}")
    @ResponseBody
    public ResponseEntity<ApiResponse<ScanResponse>> getHistoryRecord(
            @PathVariable("id") Long id,
            Authentication authentication) {
        User user = userService.getUserByEmail(authentication.getName());
        ScanResponse scan = scanService.getScanResponseByIdAndUser(id, user);
        return ResponseEntity.ok(ApiResponse.ok(scan));
    }

    @DeleteMapping("/api/history/{id}")
    @ResponseBody
    public ResponseEntity<ApiResponse<String>> deleteHistoryRecord(
            @PathVariable("id") Long id,
            Authentication authentication) {
        User user = userService.getUserByEmail(authentication.getName());
        scanService.deleteScan(id, user);
        return ResponseEntity.ok(ApiResponse.ok("Record deleted successfully", "Scan #" + id + " was deleted."));
    }
}
