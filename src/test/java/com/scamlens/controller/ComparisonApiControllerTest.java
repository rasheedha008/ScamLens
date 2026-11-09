package com.scamlens.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scamlens.dto.ComparisonRequest;
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
class ComparisonApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Should compare two messages and determine higher risk message correctly")
    void testCompareEndpoint() throws Exception {
        ComparisonRequest request = new ComparisonRequest(
                "Your account will be blocked within 24 hours. Share your OTP immediately to verify: http://bank.auth.xyz",
                "SMS",
                "Alert from State Bank: Never share your OTP with anyone. Bank will never ask for credentials.",
                "SMS"
        );

        mockMvc.perform(post("/api/compare")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.data.higherRiskMessage", is("Message A")))
                .andExpect(jsonPath("$.data.scoreDifference", greaterThan(40)))
                .andExpect(jsonPath("$.data.scanA.contextEvaluation.intentType", is("ACTIVE_SCAM_REQUEST")))
                .andExpect(jsonPath("$.data.scanB.contextEvaluation.intentType", is("LEGITIMATE_WARNING")))
                .andExpect(jsonPath("$.data.scanA.scoreBreakdown.finalScore", greaterThan(50)))
                .andExpect(jsonPath("$.data.mainDifferences", not(empty())))
                .andExpect(jsonPath("$.data.safetyNotice", notNullValue()));
    }
}
