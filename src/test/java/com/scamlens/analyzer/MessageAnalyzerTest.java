package com.scamlens.analyzer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MessageAnalyzerTest {

    private MessageAnalyzer messageAnalyzer;

    @BeforeEach
    void setUp() {
        messageAnalyzer = new MessageAnalyzer();
    }

    @Test
    @DisplayName("Should split message into separate sentences correctly")
    void testSplitSentences() {
        String text = "Dear customer. Your account is locked! Please verify now? Thank you.";
        List<String> sentences = messageAnalyzer.splitSentences(text);

        assertEquals(4, sentences.size());
        assertEquals("Dear customer.", sentences.get(0));
        assertEquals("Your account is locked!", sentences.get(1));
    }

    @Test
    @DisplayName("Should extract monetary values from text")
    void testExtractMonetaryMentions() {
        String text = "Congratulations, you won $1,000,000 in the draw. Transfer Rs. 500 processing fee.";
        List<String> amounts = messageAnalyzer.extractMonetaryMentions(text);

        assertFalse(amounts.isEmpty());
        assertTrue(amounts.stream().anyMatch(a -> a.contains("1,000,000")));
    }

    @Test
    @DisplayName("Should extract telephone numbers")
    void testExtractPhoneNumbers() {
        String text = "Contact our executive at 1800-555-0192 or 9876543210 immediately.";
        List<String> phones = messageAnalyzer.extractPhoneNumbers(text);

        assertFalse(phones.isEmpty());
    }

    @Test
    @DisplayName("Should detect excessive uppercase lettering shouting")
    void testHasExcessiveUppercase() {
        String shouting = "FINAL WARNING: YOUR ACCOUNT WILL BE TERMINATED IMMEDIATELY RIGHT NOW";
        String normal = "Hello Alex, hope you have a great day ahead.";

        assertTrue(messageAnalyzer.hasExcessiveUppercase(shouting));
        assertFalse(messageAnalyzer.hasExcessiveUppercase(normal));
    }

    @Test
    @DisplayName("Should detect excessive punctuation anomalies")
    void testHasExcessivePunctuation() {
        String urgent = "Claim your prize now!!! Is this real???";
        String calm = "Your meeting is scheduled for 3 PM.";

        assertTrue(messageAnalyzer.hasExcessivePunctuation(urgent));
        assertFalse(messageAnalyzer.hasExcessivePunctuation(calm));
    }
}
