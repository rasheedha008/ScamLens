package com.scamlens.analyzer;

import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class MessageAnalyzer {

    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "\\b(?:\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b"
    );

    private static final Pattern CURRENCY_PATTERN = Pattern.compile(
            "(\\$|€|£|₹|Rs\\.?|INR|USD)\\s?([0-9,]+(\\.[0-9]{2})?)|([0-9,]+)\\s?(dollars|rupees|lakhs?|crores?|pounds)",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern EXCESSIVE_PUNCTUATION = Pattern.compile(
            "[!?]{2,}"
    );

    /**
     * Splits message into individual sentences for contextual inspection.
     */
    public List<String> splitSentences(String text) {
        if (text == null || text.trim().isEmpty()) {
            return Collections.emptyList();
        }
        String[] raw = text.split("(?<=[.!?\\n])\\s+");
        List<String> list = new ArrayList<>();
        for (String s : raw) {
            String trimmed = s.trim();
            if (!trimmed.isEmpty()) {
                list.add(trimmed);
            }
        }
        return list;
    }

    /**
     * Extracts currency/money mentions from text.
     */
    public List<String> extractMonetaryMentions(String text) {
        if (text == null) {
            return Collections.emptyList();
        }
        List<String> amounts = new ArrayList<>();
        Matcher matcher = CURRENCY_PATTERN.matcher(text);
        while (matcher.find()) {
            amounts.add(matcher.group());
        }
        return amounts;
    }

    /**
     * Extracts phone numbers.
     */
    public List<String> extractPhoneNumbers(String text) {
        if (text == null) {
            return Collections.emptyList();
        }
        List<String> phones = new ArrayList<>();
        Matcher matcher = PHONE_PATTERN.matcher(text);
        while (matcher.find()) {
            phones.add(matcher.group());
        }
        return phones;
    }

    /**
     * Checks if the message has excessive uppercase lettering (shouting / alarmism).
     */
    public boolean hasExcessiveUppercase(String text) {
        if (text == null || text.length() < 20) {
            return false;
        }
        int upperCount = 0;
        int letterCount = 0;
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                letterCount++;
                if (Character.isUpperCase(c)) {
                    upperCount++;
                }
            }
        }
        return letterCount > 15 && ((double) upperCount / letterCount) > 0.45;
    }

    /**
     * Checks for multiple exclamation/question marks like "!!!" or "???".
     */
    public boolean hasExcessivePunctuation(String text) {
        if (text == null) {
            return false;
        }
        return EXCESSIVE_PUNCTUATION.matcher(text).find();
    }
}
