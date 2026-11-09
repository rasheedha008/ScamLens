package com.scamlens.controller;

import com.scamlens.model.Scan;
import com.scamlens.model.User;
import com.scamlens.repository.ScanRepository;
import com.scamlens.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
class HistoryApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ScanRepository scanRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User alice;
    private User bob;
    private Scan aliceScan;
    private Scan bobScan;

    @BeforeEach
    void setUp() {
        scanRepository.deleteAll();
        userRepository.deleteAll();

        alice = new User("Alice", "alice@example.com", passwordEncoder.encode("Password123"));
        alice = userRepository.save(alice);

        bob = new User("Bob", "bob@example.com", passwordEncoder.encode("Password123"));
        bob = userRepository.save(bob);

        aliceScan = new Scan();
        aliceScan.setUser(alice);
        aliceScan.setOriginalMessage("Alice private message");
        aliceScan.setSourceType("SMS");
        aliceScan.setRiskScore(40);
        aliceScan.setRiskLevel("Medium");
        aliceScan = scanRepository.save(aliceScan);

        bobScan = new Scan();
        bobScan.setUser(bob);
        bobScan.setOriginalMessage("Bob private message");
        bobScan.setSourceType("Email");
        bobScan.setRiskScore(85);
        bobScan.setRiskLevel("Critical");
        bobScan = scanRepository.save(bobScan);
    }

    @Test
    @WithMockUser(username = "alice@example.com", roles = {"USER"})
    @DisplayName("Alice should be able to view her own scan by ID")
    void testAliceViewOwnScan() throws Exception {
        mockMvc.perform(get("/api/history/" + aliceScan.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.data.id", is(aliceScan.getId().intValue())));
    }

    @Test
    @WithMockUser(username = "alice@example.com", roles = {"USER"})
    @DisplayName("Alice must NOT be allowed to view Bob's scan (Unauthorized Access Prevention)")
    void testAliceCannotViewBobScan() throws Exception {
        mockMvc.perform(get("/api/history/" + bobScan.getId()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)));
    }

    @Test
    @WithMockUser(username = "alice@example.com", roles = {"USER"})
    @DisplayName("Alice must NOT be allowed to delete Bob's scan")
    void testAliceCannotDeleteBobScan() throws Exception {
        mockMvc.perform(delete("/api/history/" + bobScan.getId()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)));
    }

    @Test
    @WithMockUser(username = "alice@example.com", roles = {"USER"})
    @DisplayName("Authenticated user should render history page with non-empty scans successfully")
    void testHistoryPageAuthenticated() throws Exception {
        mockMvc.perform(get("/history"))
                .andExpect(status().isOk())
                .andExpect(view().name("history"))
                .andExpect(model().attributeExists("scans"))
                .andExpect(model().attributeExists("user"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Private Scan History")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Alice private message")));
    }

    @Test
    @DisplayName("Unauthenticated visitor to /history should be redirected to /login")
    void testHistoryPageUnauthenticatedRedirect() throws Exception {
        mockMvc.perform(get("/history"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("/login")));
    }
}
