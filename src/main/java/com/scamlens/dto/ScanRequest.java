package com.scamlens.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ScanRequest {

    @NotBlank(message = "Message content cannot be empty")
    @Size(max = 10000, message = "Message content must not exceed 10,000 characters")
    private String message;

    private String sourceType = "Auto Detect";

    public ScanRequest() {
    }

    public ScanRequest(String message, String sourceType) {
        this.message = message;
        this.sourceType = (sourceType != null && !sourceType.trim().isEmpty()) ? sourceType : "Auto Detect";
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getSourceType() {
        return sourceType;
    }

    public void setSourceType(String sourceType) {
        this.sourceType = sourceType;
    }
}
