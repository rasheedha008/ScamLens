package com.scamlens.controller;

import com.scamlens.dto.ScanResponse;
import com.scamlens.model.User;
import com.scamlens.service.ReportService;
import com.scamlens.service.ScanService;
import com.scamlens.service.UserService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class ReportController {

    private final ReportService reportService;
    private final ScanService scanService;
    private final UserService userService;

    public ReportController(ReportService reportService, ScanService scanService, UserService userService) {
        this.reportService = reportService;
        this.scanService = scanService;
        this.userService = userService;
    }

    @GetMapping("/api/report/{id}/pdf")
    public ResponseEntity<byte[]> downloadPdfReport(@PathVariable("id") Long id,
                                                   Authentication authentication) {
        User user = userService.getUserByEmail(authentication.getName());
        ScanResponse scan = scanService.getScanResponseByIdAndUser(id, user);

        try {
            byte[] pdfBytes = reportService.generatePdfReport(scan);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "scamlens-scan-report-" + id + ".pdf");
            headers.setContentLength(pdfBytes.length);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(pdfBytes);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}
