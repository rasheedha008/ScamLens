package com.scamlens.analyzer;

import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Normalizes Tamil Unicode text, strips invisible control characters,
 * preserves English technical acronyms (OTP, PIN, UPI, KYC, SMS, URL),
 * and provides context-aware Tamil sentence segmentation.
 */
@Component
public class TamilTextNormalizer {

    private static final Pattern ZERO_WIDTH_CHARS = Pattern.compile("[\\u200B-\\u200D\\uFEFF\\u200E\\u200F\\u00AD]");
    private static final Pattern EXCESSIVE_WHITESPACE = Pattern.compile("[\\r\\t\\f ]+");
    private static final Pattern TAMIL_SENTENCE_BOUNDARY = Pattern.compile("(?<=[.!?\\n\\u0964])\\s+");

    /**
     * Normalizes Tamil text:
     * 1. Applies Unicode NFC decomposition-composition normalization.
     * 2. Removes zero-width characters (ZWJ, ZWNJ, BOM).
     * 3. Normalizes whitespace while preserving English uppercase technical tokens.
     */
    public String normalize(String text) {
        if (text == null) {
            return "";
        }

        // 1. Unicode NFC normalization
        String normalized = Normalizer.normalize(text, Normalizer.Form.NFC);

        // 2. Remove invisible zero-width and directional control characters
        normalized = ZERO_WIDTH_CHARS.matcher(normalized).replaceAll("");

        // 3. Normalize whitespace
        normalized = EXCESSIVE_WHITESPACE.matcher(normalized).replaceAll(" ").trim();

        return normalized;
    }

    /**
     * Splits Tamil text into contextual sentences.
     */
    public List<String> splitSentences(String text) {
        if (text == null || text.trim().isEmpty()) {
            return Collections.emptyList();
        }

        String normalized = normalize(text);
        String[] rawSentences = TAMIL_SENTENCE_BOUNDARY.split(normalized);
        List<String> sentences = new ArrayList<>();

        for (String s : rawSentences) {
            String trimmed = s.trim();
            if (!trimmed.isEmpty()) {
                sentences.add(trimmed);
            }
        }

        // If no punctuation was used, return the whole text as single sentence
        if (sentences.isEmpty()) {
            sentences.add(normalized);
        }

        return sentences;
    }

    /**
     * Case-insensitive substring matching that works for both Tamil script and embedded English tokens.
     */
    public boolean containsIgnoreCase(String source, String target) {
        if (source == null || target == null) {
            return false;
        }
        return source.toLowerCase().contains(target.toLowerCase());
    }
}
