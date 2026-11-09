package com.scamlens.analyzer;

import com.scamlens.model.UrlFinding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UrlAnalyzerTest {

    private UrlAnalyzer urlAnalyzer;

    @BeforeEach
    void setUp() {
        urlAnalyzer = new UrlAnalyzer();
    }

    @Test
    @DisplayName("Should extract single and multiple URLs from text")
    void testExtractUrls() {
        String text = "Check out https://example.com/login and http://test.org/auth for details.";
        List<String> urls = urlAnalyzer.extractUrls(text);

        assertEquals(2, urls.size());
        assertTrue(urls.contains("https://example.com/login"));
        assertTrue(urls.contains("http://test.org/auth"));
    }

    @Test
    @DisplayName("Should handle messages without any URLs")
    void testExtractUrlsEmpty() {
        String text = "Hello friend, see you at 6 PM tomorrow.";
        List<String> urls = urlAnalyzer.extractUrls(text);

        assertTrue(urls.isEmpty());
    }

    @Test
    @DisplayName("Should detect URL shorteners")
    void testDetectShorteners() {
        UrlFinding finding = urlAnalyzer.analyzeUrl("https://bit.ly/3xY8Z9");
        assertTrue(finding.isShortener());
        assertTrue(finding.isSuspicious());
    }

    @Test
    @DisplayName("Should detect IP address host")
    void testDetectIpHost() {
        UrlFinding finding = urlAnalyzer.analyzeUrl("http://192.168.1.55/login");
        assertTrue(finding.isIpHost());
        assertTrue(finding.isSuspicious());
    }

    @Test
    @DisplayName("Should detect deceptive user-info @ syntax")
    void testDetectUserInfoSyntax() {
        UrlFinding finding = urlAnalyzer.analyzeUrl("https://paypal.com@badsite.ru/verify");
        assertTrue(finding.isUserInfoPresent());
        assertTrue(finding.isSuspicious());
    }

    @Test
    @DisplayName("Should detect Punycode / IDN homograph spoofing")
    void testDetectPunycode() {
        UrlFinding finding = urlAnalyzer.analyzeUrl("https://xn--pypal-4ve.com/signin");
        assertTrue(finding.isPunycode());
        assertTrue(finding.isSuspicious());
    }

    @Test
    @DisplayName("Should detect excessive subdomains and suspicious TLDs")
    void testDetectSubdomainsAndTld() {
        UrlFinding finding = urlAnalyzer.analyzeUrl("http://login.secure.update.bank.verify.xyz/auth");
        assertTrue(finding.isExcessiveSubdomains());
        assertTrue(finding.isSuspiciousTld());
        assertTrue(finding.isSuspicious());
    }

    @Test
    @DisplayName("Should detect brand keyword outside genuine domain")
    void testDetectBrandImpersonationInUrl() {
        UrlFinding finding = urlAnalyzer.analyzeUrl("http://paypal-security-check.online/login");
        assertTrue(finding.isSuspicious());
        assertTrue(finding.getReasons().stream().anyMatch(r -> r.contains("paypal")));
    }

    @Test
    @DisplayName("Should handle malformed URL safely without throwing exceptions")
    void testMalformedUrlSafeHandling() {
        UrlFinding finding = urlAnalyzer.analyzeUrl("http://:broken^syntax%url");
        assertNotNull(finding);
        assertTrue(finding.isSuspicious());
    }
}
