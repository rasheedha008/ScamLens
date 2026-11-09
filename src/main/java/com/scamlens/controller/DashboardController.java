package com.scamlens.controller;

import com.scamlens.dto.ApiResponse;
import com.scamlens.dto.DashboardStatsDto;
import com.scamlens.dto.ScanResponse;
import com.scamlens.model.User;
import com.scamlens.service.DashboardService;
import com.scamlens.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Controller
public class DashboardController {

    private final DashboardService dashboardService;
    private final UserService userService;

    public DashboardController(DashboardService dashboardService, UserService userService) {
        this.dashboardService = dashboardService;
        this.userService = userService;
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            return "redirect:/login";
        }
        User user = userService.getUserByEmail(authentication.getName());
        DashboardStatsDto stats = dashboardService.getUserDashboardStats(user);
        model.addAttribute("user", user);
        model.addAttribute("stats", stats);
        return "dashboard";
    }

    @GetMapping("/api/dashboard/stats")
    @ResponseBody
    public ResponseEntity<ApiResponse<DashboardStatsDto>> getStats(Authentication authentication) {
        User user = userService.getUserByEmail(authentication.getName());
        DashboardStatsDto stats = dashboardService.getUserDashboardStats(user);
        return ResponseEntity.ok(ApiResponse.ok(stats));
    }

    @GetMapping("/api/dashboard/recent-scans")
    @ResponseBody
    public ResponseEntity<ApiResponse<List<ScanResponse>>> getRecentScans(Authentication authentication) {
        User user = userService.getUserByEmail(authentication.getName());
        DashboardStatsDto stats = dashboardService.getUserDashboardStats(user);
        return ResponseEntity.ok(ApiResponse.ok(stats.getRecentScans()));
    }
}
