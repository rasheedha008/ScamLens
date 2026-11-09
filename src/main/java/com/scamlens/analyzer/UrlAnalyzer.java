package com.scamlens.analyzer;

import com.scamlens.model.UrlFinding;
import org.springframework.stereotype.Component;

import java.net.IDN;
import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class UrlAnalyzer {

    // Regex to match URLs in text (http, https, or bare www/domain patterns)
    private static final Pattern URL_PATTERN = Pattern.compile(
            "\\b(?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\((?:[^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\((?:[^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’])",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}(:\\d+)?$"
    );

    private static final Set<String> KNOWN_SHORTENERS = new HashSet<>(Arrays.asList(
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
            "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly",
            "lnkd.in", "s.id", "soo.gd", "bc.vc", "shorte.st"
    ));

    private static final Set<String> SUSPICIOUS_TLDS = new HashSet<>(Arrays.asList(
            "xyz", "top", "tk", "ml", "cf", "gq", "buzz", "work", "click",
            "rest", "cam", "fit", "icu", "surf", "monster", "bar", "live", "link"
    ));

    private static final List<String> WELL_KNOWN_BRANDS = Arrays.asList(
            "paypal", "netflix", "amazon", "apple", "microsoft", "google",
            "facebook", "instagram", "whatsapp", "wellsfargo", "chase",
            "bankofamerica", "citi", "binance", "coinbase", "telegram",
            "sbi", "hdfc", "icici", "axis", "fedex", "dhl", "ups", "usps", "bank"
    );

    private static final Pattern SUSPICIOUS_PARAM_PATTERN = Pattern.compile(
            "(token|session|redirect|return|next|auth|key|password|credential|login|verify)=",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Extracts all raw URLs from the text message.
     */
    public List<String> extractUrls(String text) {
        if (text == null || text.trim().isEmpty()) {
            return Collections.emptyList();
        }
        List<String> urls = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String url = matcher.group().trim();
            urls.add(url);
        }
        return urls;
    }

    /**
     * Performs passive, non-executing heuristic inspection on a single URL.
     */
    public UrlFinding analyzeUrl(String rawUrl) {
        UrlFinding finding = new UrlFinding(rawUrl);
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return finding;
        }

        String normalizedUrl = rawUrl.trim();
        if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
            normalizedUrl = "http://" + normalizedUrl;
        }

        try {
            URI uri = new URI(normalizedUrl);
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "http";
            String host = uri.getHost();
            String userInfo = uri.getUserInfo();
            String path = uri.getPath();
            String query = uri.getQuery();

            finding.setScheme(scheme);
            finding.setDomain(host != null ? host : "");

            int score = 0;

            // 1. Weak warning: Insecure HTTP
            if ("http".equalsIgnoreCase(scheme)) {
                finding.setInsecureHttp(true);
                finding.addReason("Insecure HTTP protocol used instead of encrypted HTTPS.");
                score += 5;
            }

            if (host != null && !host.isEmpty()) {
                String hostLower = host.toLowerCase();

                // 2. Punycode check (homograph attack)
                String asciiHost = IDN.toASCII(hostLower);
                if (hostLower.startsWith("xn--") || asciiHost.contains("xn--")) {
                    finding.setPunycode(true);
                    finding.addReason("Punycode / Internationalized Domain Name detected (common homograph deception).");
                    score += 25;
                }

                // 3. IP address host
                if (IP_PATTERN.matcher(hostLower).matches() || hostLower.matches("^\\[?[0-9a-fA-F:]+\\]?$")) {
                    finding.setIpHost(true);
                    finding.addReason("Direct IP address used as host instead of a registered domain name.");
                    score += 30;
                }

                // 4. URL shortener check
                for (String shortener : KNOWN_SHORTENERS) {
                    if (hostLower.equals(shortener) || hostLower.endsWith("." + shortener)) {
                        finding.setShortener(true);
                        finding.addReason("URL shortener used (" + shortener + "), which conceals the destination target.");
                        score += 15;
                        break;
                    }
                }

                // 5. Excessive subdomains
                String[] domainParts = hostLower.split("\\.");
                if (domainParts.length >= 4 && !finding.isIpHost()) {
                    finding.setExcessiveSubdomains(true);
                    finding.addReason("Excessive subdomain depth (" + domainParts.length + " levels), often used to mimic trusted brands.");
                    score += 15;
                }

                // 6. Suspicious TLD
                if (domainParts.length >= 2) {
                    String tld = domainParts[domainParts.length - 1];
                    if (SUSPICIOUS_TLDS.contains(tld)) {
                        finding.setSuspiciousTld(true);
                        finding.addReason("Uncommon or high-abuse Top-Level Domain (." + tld + ") detected.");
                        score += 15;
                    }
                }

                // 7. Misleading domain structure / Brand impersonation in subdomains or path
                String rawLower = rawUrl.toLowerCase();
                for (String brand : WELL_KNOWN_BRANDS) {
                    if (rawLower.contains(brand)) {
                        // Check if the brand appears in subdomains or path rather than the genuine domain
                        boolean genuine = hostLower.equals(brand + ".com") || hostLower.endsWith("." + brand + ".com") ||
                                          hostLower.equals(brand + ".co.in") || hostLower.endsWith("." + brand + ".co.in") ||
                                          hostLower.equals(brand + ".org") || hostLower.endsWith("." + brand + ".org");
                        if (!genuine) {
                            finding.addReason("Brand keyword '" + brand + "' detected in URL structure outside its legitimate domain.");
                            score += 25;
                            break;
                        }
                    }
                }
            }

            // 8. UserInfo in URL (@ symbol deceptive redirection)
            if (userInfo != null && !userInfo.isEmpty()) {
                finding.setUserInfoPresent(true);
                finding.addReason("Suspicious user-info section present before '@' symbol in URL, which disguises actual host.");
                score += 30;
            } else if (rawUrl.contains("@")) {
                finding.setUserInfoPresent(true);
                finding.addReason("URL contains '@' symbol, which may redirect traffic to an unintended destination.");
                score += 25;
            }

            // 9. Suspicious URL parameters
            if (query != null && SUSPICIOUS_PARAM_PATTERN.matcher(query).find()) {
                finding.addReason("URL query string contains authentication or redirect parameters often used in phishing links.");
                score += 10;
            }

            // 10. Suspicious path segments
            if (path != null) {
                String pathLower = path.toLowerCase();
                if (pathLower.contains(".exe") || pathLower.contains(".apk") || pathLower.contains(".scr") || pathLower.contains(".zip")) {
                    finding.addReason("URL points directly to an executable, archive, or mobile installation file.");
                    score += 30;
                }
                if (pathLower.contains("/login") || pathLower.contains("/signin") || pathLower.contains("/verify") || pathLower.contains("/secure")) {
                    if (finding.isSuspicious() || score > 10) {
                        finding.addReason("URL path attempts to impersonate authentication or account verification.");
                        score += 15;
                    }
                }
            }

            finding.setRiskScore(Math.min(100, score));
            finding.setSuspicious(score >= 15);

        } catch (Exception e) {
            // Malformed URL
            finding.addReason("Malformed or deceptive URL syntax: " + e.getMessage());
            finding.setSuspicious(true);
            finding.setRiskScore(25);
        }

        return finding;
    }

    private String extractRegisteredDomain(String host) {
        String[] parts = host.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return host;
    }
}
