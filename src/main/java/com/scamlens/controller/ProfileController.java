package com.scamlens.controller;

import com.scamlens.dto.ApiResponse;
import com.scamlens.dto.UserProfileDto;
import com.scamlens.model.User;
import com.scamlens.repository.ScanRepository;
import com.scamlens.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class ProfileController {

    private final UserService userService;
    private final ScanRepository scanRepository;

    public ProfileController(UserService userService, ScanRepository scanRepository) {
        this.userService = userService;
        this.scanRepository = scanRepository;
    }

    @GetMapping("/profile")
    public String profilePage(Authentication authentication, Model model) {
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            return "redirect:/login";
        }
        User user = userService.getUserByEmail(authentication.getName());
        long totalScans = scanRepository.countByUser(user);

        UserProfileDto profile = new UserProfileDto();
        profile.setId(user.getId());
        profile.setName(user.getName());
        profile.setEmail(user.getEmail());
        profile.setMemberSince(user.getCreatedAt());
        profile.setTotalScans(totalScans);

        model.addAttribute("profile", profile);
        model.addAttribute("user", user);
        return "profile";
    }

    @GetMapping("/api/profile")
    @ResponseBody
    public ResponseEntity<ApiResponse<UserProfileDto>> getProfile(Authentication authentication) {
        User user = userService.getUserByEmail(authentication.getName());
        long totalScans = scanRepository.countByUser(user);

        UserProfileDto profile = new UserProfileDto();
        profile.setId(user.getId());
        profile.setName(user.getName());
        profile.setEmail(user.getEmail());
        profile.setMemberSince(user.getCreatedAt());
        profile.setTotalScans(totalScans);

        return ResponseEntity.ok(ApiResponse.ok(profile));
    }

    @PutMapping("/api/profile")
    @ResponseBody
    public ResponseEntity<ApiResponse<String>> updateProfile(@Valid @RequestBody UserProfileDto dto,
                                                            Authentication authentication) {
        userService.updateProfile(authentication.getName(), dto);
        return ResponseEntity.ok(ApiResponse.ok("Profile updated successfully", "Profile settings saved."));
    }
}
