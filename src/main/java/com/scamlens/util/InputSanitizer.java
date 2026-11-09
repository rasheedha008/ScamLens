package com.scamlens.util;

public final class InputSanitizer {

    private static final int MAX_MESSAGE_LENGTH = 10000;

    private InputSanitizer() {
    }

    public static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        // Remove null characters and excessive invisible control characters
        String cleaned = input.replaceAll("\\u0000", "").trim();

        // Enforce maximum length limit
        if (cleaned.length() > MAX_MESSAGE_LENGTH) {
            cleaned = cleaned.substring(0, MAX_MESSAGE_LENGTH);
        }

        return cleaned;
    }

    public static String escapeForDisplay(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
    }
}
