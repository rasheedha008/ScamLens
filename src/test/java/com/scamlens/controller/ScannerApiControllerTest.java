package com.scamlens.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scamlens.dto.ScanRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
class ScannerApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Should return 200 with structured analysis findings for valid scan request")
    void testAnalyzeEndpointValid() throws Exception {
        ScanRequest request = new ScanRequest(
                "Urgent: Share your OTP immediately to verify your account at http://login.bank.xyz",
                "SMS"
        );

        mockMvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.data.riskScore", greaterThan(40)))
                .andExpect(jsonPath("$.data.riskLevel", anyOf(is("High"), is("Critical"))))
                .andExpect(jsonPath("$.data.categories", hasItem("OTP and Credential Theft")))
                .andExpect(jsonPath("$.data.contextEvaluation.intentType", is("ACTIVE_SCAM_REQUEST")))
                .andExpect(jsonPath("$.data.scoreBreakdown.finalScore", greaterThan(40)))
                .andExpect(jsonPath("$.data.urlFindings", not(empty())));
    }

    @Test
    @DisplayName("Should return 400 Bad Request when message is blank")
    void testAnalyzeEndpointEmptyMessage() throws Exception {
        ScanRequest request = new ScanRequest("", "SMS");

        mockMvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)));
    }
}
