package com.scamlens.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ComparisonRequest {

    @NotBlank(message = "Message A is required")
    @Size(max = 10000, message = "Message A must not exceed 10,000 characters")
    private String messageA;

    private String sourceTypeA = "Auto Detect";

    @NotBlank(message = "Message B is required")
    @Size(max = 10000, message = "Message B must not exceed 10,000 characters")
    private String messageB;

    private String sourceTypeB = "Auto Detect";

    public ComparisonRequest() {
    }

    public ComparisonRequest(String messageA, String sourceTypeA, String messageB, String sourceTypeB) {
        this.messageA = messageA;
        this.sourceTypeA = sourceTypeA;
        this.messageB = messageB;
        this.sourceTypeB = sourceTypeB;
    }

    public String getMessageA() {
        return messageA;
    }

    public void setMessageA(String messageA) {
        this.messageA = messageA;
    }

    public String getSourceTypeA() {
        return sourceTypeA;
    }

    public void setSourceTypeA(String sourceTypeA) {
        this.sourceTypeA = sourceTypeA;
    }

    public String getMessageB() {
        return messageB;
    }

    public void setMessageB(String messageB) {
        this.messageB = messageB;
    }

    public String getSourceTypeB() {
        return sourceTypeB;
    }

    public void setSourceTypeB(String sourceTypeB) {
        this.sourceTypeB = sourceTypeB;
    }
}
