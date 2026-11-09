package com.scamlens.service;

import com.scamlens.analyzer.UrlAnalyzer;
import com.scamlens.model.ScamIndicator;
import com.scamlens.model.UrlFinding;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UrlAnalysisService {

    private final UrlAnalyzer urlAnalyzer;

    public UrlAnalysisService(UrlAnalyzer urlAnalyzer) {
        this.urlAnalyzer = urlAnalyzer;
    }

    /**
     * Extracts and passively analyzes all URLs contained within the message.
     */
    public List<UrlFinding> analyzeUrlsInText(String text) {
        List<String> rawUrls = urlAnalyzer.extractUrls(text);
        List<UrlFinding> findings = new ArrayList<>();

        for (String url : rawUrls) {
            UrlFinding finding = urlAnalyzer.analyzeUrl(url);
            findings.add(finding);
        }

        return findings;
    }

    /**
     * Translates URL findings into weighted ScamIndicators.
     */
    public List<ScamIndicator> extractUrlIndicators(List<UrlFinding> findings) {
        List<ScamIndicator> indicators = new ArrayList<>();

        for (UrlFinding finding : findings) {
            boolean addedSpecific = false;

            if (finding.isShortener()) {
                indicators.add(new ScamIndicator(
                        "URL_SHORT",
                        "URL Shortener Concealment",
                        "Suspicious URL",
                        15,
                        finding.getOriginalUrl(),
                        "The message uses a URL shortener (" + finding.getDomain() + ") that obscures the final destination domain."
                ));
                addedSpecific = true;
            }

            if (finding.isIpHost()) {
                indicators.add(new ScamIndicator(
                        "URL_IP",
                        "Raw IP Address Host",
                        "Suspicious URL",
                        25,
                        finding.getOriginalUrl(),
                        "The link connects directly to an unmapped IP address (" + finding.getDomain() + "), bypassing DNS domain vetting."
                ));
                addedSpecific = true;
            }

            if (finding.isPunycode()) {
                indicators.add(new ScamIndicator(
                        "URL_PUNYCODE",
                        "Punycode Homograph Spoofing",
                        "Suspicious URL",
                        25,
                        finding.getOriginalUrl(),
                        "The domain contains internationalized Punycode characters mimicking standard Latin letters."
                ));
                addedSpecific = true;
            }

            if (finding.isUserInfoPresent()) {
                indicators.add(new ScamIndicator(
                        "URL_USERINFO",
                        "Deceptive @ Redirection Syntax",
                        "Suspicious URL",
                        25,
                        finding.getOriginalUrl(),
                        "The URL embeds '@' user-info credentials designed to deceive users regarding the genuine destination server."
                ));
                addedSpecific = true;
            }

            if (finding.isSuspiciousTld()) {
                indicators.add(new ScamIndicator(
                        "URL_TLD",
                        "High-Abuse Top-Level Domain",
                        "Suspicious URL",
                        15,
                        finding.getOriginalUrl(),
                        "The destination employs an uncommon or high-abuse top-level domain frequently utilized in phishing."
                ));
                addedSpecific = true;
            }

            boolean hasBrandSpoof = finding.getReasons().stream().anyMatch(r -> r.toLowerCase().contains("brand keyword"));
            if (hasBrandSpoof) {
                indicators.add(new ScamIndicator(
                        "URL_BRAND",
                        "Brand Keyword Deception in URL",
                        "Suspicious URL",
                        25,
                        finding.getOriginalUrl(),
                        "A recognized brand or banking keyword is embedded in the URL outside its authentic registered domain."
                ));
                addedSpecific = true;
            }

            boolean hasAuthParams = finding.getReasons().stream().anyMatch(r -> r.toLowerCase().contains("authentication or redirect"));
            if (hasAuthParams) {
                indicators.add(new ScamIndicator(
                        "URL_AUTH_PARAM",
                        "Phishing Authentication Parameter in URL",
                        "Suspicious URL",
                        15,
                        finding.getOriginalUrl(),
                        "The link embeds token, verification, or credential parameters typically used in credential harvest targets."
                ));
                addedSpecific = true;
            }

            if (!addedSpecific && finding.isSuspicious()) {
                indicators.add(new ScamIndicator(
                        "URL_SUSP",
                        "Suspicious Destination Domain",
                        "Suspicious URL",
                        20,
                        finding.getOriginalUrl(),
                        String.join("; ", finding.getReasons())
                ));
            }
        }

        return indicators;
    }
}
