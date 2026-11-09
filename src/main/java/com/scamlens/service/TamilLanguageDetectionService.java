package com.scamlens.service;

import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

/**
 * Service to detect Tamil script content and determine language composition.
 * Strict Constraint: Analyzes authentic Tamil script (Unicode \u0B80-\u0BFF).
 * Tanglish (Tamil in English alphabet) is explicitly excluded from detection.
 */
@Service
public class TamilLanguageDetectionService {

    public static final String LANG_TAMIL = "Tamil";
    public static final String LANG_ENGLISH = "English";
    public static final String LANG_MULTILINGUAL = "Multilingual (Tamil + English)";

    public static final String CODE_TAMIL = "ta";
    public static final String CODE_ENGLISH = "en";

    // Tamil Unicode Block: U+0B80 to U+0BFF
    private static final Pattern TAMIL_CHAR_PATTERN = Pattern.compile("[\\u0B80-\\u0BFF]");

    /**
     * Checks if the text contains any Tamil script character.
     */
    public boolean containsTamil(String text) {
        if (text == null || text.trim().isEmpty()) {
            return false;
        }
        return TAMIL_CHAR_PATTERN.matcher(text).find();
    }

    /**
     * Determines whether the primary language is Tamil, English, or Multilingual.
     */
    public String detectLanguage(String text) {
        if (text == null || text.trim().isEmpty()) {
            return LANG_ENGLISH;
        }

        int tamilChars = countTamilCharacters(text);
        if (tamilChars == 0) {
            return LANG_ENGLISH;
        }

        int latinChars = countLatinLetters(text);

        // If predominantly Tamil script or mixed with technical tokens (OTP, PIN, URL)
        if (latinChars == 0 || (double) tamilChars / (tamilChars + latinChars) >= 0.35) {
            return (latinChars > 15) ? LANG_MULTILINGUAL : LANG_TAMIL;
        }

        return LANG_MULTILINGUAL;
    }

    /**
     * Returns ISO language code: "ta" or "en".
     */
    public String getLanguageCode(String text) {
        return containsTamil(text) ? CODE_TAMIL : CODE_ENGLISH;
    }

    /**
     * Counts characters falling within the Tamil Unicode block.
     */
    public int countTamilCharacters(String text) {
        if (text == null) return 0;
        int count = 0;
        for (char c : text.toCharArray()) {
            if (c >= '\u0B80' && c <= '\u0BFF') {
                count++;
            }
        }
        return count;
    }

    /**
     * Counts standard ASCII Latin letters.
     */
    public int countLatinLetters(String text) {
        if (text == null) return 0;
        int count = 0;
        for (char c : text.toCharArray()) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                count++;
            }
        }
        return count;
    }

    /**
     * Computes ratio of Tamil characters to total alphabetic characters.
     */
    public double getTamilRatio(String text) {
        if (text == null || text.isEmpty()) return 0.0;
        int tamil = countTamilCharacters(text);
        int latin = countLatinLetters(text);
        int total = tamil + latin;
        return total > 0 ? ((double) tamil / total) : 0.0;
    }
}
