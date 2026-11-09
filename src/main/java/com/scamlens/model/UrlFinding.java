package com.scamlens.model;

import java.util.ArrayList;
import java.util.List;

public class UrlFinding {

    private String originalUrl;
    private String domain;
    private String scheme;
    private boolean suspicious;
    private int riskScore;
    private List<String> reasons = new ArrayList<>();
    private boolean ipHost;
    private boolean shortener;
    private boolean punycode;
    private boolean excessiveSubdomains;
    private boolean userInfoPresent;
    private boolean suspiciousTld;
    private boolean insecureHttp;

    public UrlFinding() {
    }

    public UrlFinding(String originalUrl) {
        this.originalUrl = originalUrl;
    }

    public void addReason(String reason) {
        this.reasons.add(reason);
        this.suspicious = true;
    }

    public String getOriginalUrl() {
        return originalUrl;
    }

    public void setOriginalUrl(String originalUrl) {
        this.originalUrl = originalUrl;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getScheme() {
        return scheme;
    }

    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    public boolean isSuspicious() {
        return suspicious;
    }

    public void setSuspicious(boolean suspicious) {
        this.suspicious = suspicious;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public List<String> getReasons() {
        return reasons;
    }

    public void setReasons(List<String> reasons) {
        this.reasons = reasons;
    }

    public boolean isIpHost() {
        return ipHost;
    }

    public void setIpHost(boolean ipHost) {
        this.ipHost = ipHost;
    }

    public boolean isShortener() {
        return shortener;
    }

    public void setShortener(boolean shortener) {
        this.shortener = shortener;
    }

    public boolean isPunycode() {
        return punycode;
    }

    public void setPunycode(boolean punycode) {
        this.punycode = punycode;
    }

    public boolean isExcessiveSubdomains() {
        return excessiveSubdomains;
    }

    public void setExcessiveSubdomains(boolean excessiveSubdomains) {
        this.excessiveSubdomains = excessiveSubdomains;
    }

    public boolean isUserInfoPresent() {
        return userInfoPresent;
    }

    public void setUserInfoPresent(boolean userInfoPresent) {
        this.userInfoPresent = userInfoPresent;
    }

    public boolean isSuspiciousTld() {
        return suspiciousTld;
    }

    public void setSuspiciousTld(boolean suspiciousTld) {
        this.suspiciousTld = suspiciousTld;
    }

    public boolean isInsecureHttp() {
        return insecureHttp;
    }

    public void setInsecureHttp(boolean insecureHttp) {
        this.insecureHttp = insecureHttp;
    }
}
