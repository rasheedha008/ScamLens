package com.scamlens.analyzer;

import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Detects sensitive credential targets in Tamil script and identifies whether
 * the credentials are being requested, merely mentioned, or warned against.
 */
@Component
public class TamilCredentialDetector {

    public enum CredentialIntent {
        REQUESTED,
        WARNED_AGAINST,
        MENTIONED_ONLY
    }

    public static class CredentialMatch {
        private final String term;
        private final String englishName;
        private final CredentialIntent intent;
        private final String matchedContext;

        public CredentialMatch(String term, String englishName, CredentialIntent intent, String matchedContext) {
            this.term = term;
            this.englishName = englishName;
            this.intent = intent;
            this.matchedContext = matchedContext;
        }

        public String getTerm() {
            return term;
        }

        public String getEnglishName() {
            return englishName;
        }

        public CredentialIntent getIntent() {
            return intent;
        }

        public String getMatchedContext() {
            return matchedContext;
        }
    }

    // Comprehensive Tamil and mixed credential patterns
    private static final Map<String, Pattern> CREDENTIAL_PATTERNS = new LinkedHashMap<>();
    static {
        CREDENTIAL_PATTERNS.put("OTP", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(otp|ஓடிபி|ஒருமுறை\\s+கடவுச்சொல்|otp\\s+எண்|otp-ஐ)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("PIN", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(pin|பின்|பின்\\s+எண்|ஏடிஎம்\\s+பின்|atm\\s+pin)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("Password", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(கடவுச்சொல்|கடவுச்சொல்லை|கடவுச்சொல்லைக்|பாஸ்வேர்ட்|ரகசிய\\s+குறியீடு)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("Username", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(பயனர்\\s+பெயர்|பயனர்\\s+எண்|லாகின்\\s+ஐடி|username)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("Bank Account Details", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(வங்கி\\s+கணக்கு\\s+விவரங்கள்|வங்கி\\s+விவரங்கள்|கணக்கு\\s+எண்|வங்கி\\s+கணக்கு)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("Debit Card Details", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(பற்று\\s+அட்டை\\s+விவரங்கள்|பற்று\\s+அட்டை|டெபிட்\\s+கார்டு)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("Credit Card / CVV", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(கடன்\\s+அட்டை\\s+விவரங்கள்|கடன்\\s+அட்டை|கிரெடிட்\\s+கார்டு|cvv|சிவிவி)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("Aadhaar / Identity", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(ஆதார்\\s+எண்|ஆதார்\\s+அட்டை|பான்\\s+எண்|pan\\s+card|aadhaar)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("Personal Information", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(தனிப்பட்ட\\s+தகவல்கள்|தனிப்பட்ட\\s+விவரங்கள்|தனிப்பட்ட\\s+விவரங்களை|ரகசிய\\s+விவரங்கள்)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
        CREDENTIAL_PATTERNS.put("UPI PIN", Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(upi\\s+pin|யுபிஐ\\s+பின்|upi\\s+கடவுச்சொல்|upi\\s+ஐடி)(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS));
    }

    // Action verbs indicating extraction request in Tamil
    private static final Pattern EXTRACTION_REQUEST_PATTERN = Pattern.compile(
            "(அனுப்பவும்|அனுப்ப|வழங்கவும்|வழங்க|உள்ளிடவும்|உள்ளிட|பகிரவும்|பகிர|தெரிவிக்கவும்|பதிவிடவும்|உறுதிப்படுத்தவும்|சரிபார்க்கவும்|enter|share|send|provide)"
    );

    // Negation phrases warning against disclosing credentials
    private static final Pattern CREDENTIAL_NEGATION_PATTERN = Pattern.compile(
            "(பகிர\\s+வேண்டாம்|அனுப்ப\\s+வேண்டாம்|வழங்க\\s+வேண்டாம்|தெரிவிக்க\\s+வேண்டாம்|சொல்ல\\s+வேண்டாம்|உள்ளிட\\s+வேண்டாம்|கேட்க\\s+மாட்டார்கள்|கேட்காது|கூடாது|செய்யாதீர்கள்|never\\s+share|do\\s+not\\s+share)"
    );

    /**
     * Detects all credential mentions in a Tamil sentence and determines their extraction intent.
     */
    public List<CredentialMatch> detectCredentials(String sentence) {
        if (sentence == null || sentence.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<CredentialMatch> matches = new ArrayList<>();

        for (Map.Entry<String, Pattern> entry : CREDENTIAL_PATTERNS.entrySet()) {
            String credName = entry.getKey();
            Pattern p = entry.getValue();

            var matcher = p.matcher(sentence);
            if (matcher.find()) {
                String matchedToken = matcher.group();
                CredentialIntent intent = evaluateIntent(sentence, matchedToken);
                matches.add(new CredentialMatch(matchedToken, credName, intent, sentence));
            }
        }

        return matches;
    }

    /**
     * Determines whether the credential is being requested, warned against, or merely mentioned.
     */
    public CredentialIntent evaluateIntent(String sentence, String matchedToken) {
        // 1. Check if proximity negation exists (e.g. "OTP பகிர வேண்டாம்" or "கடவுச்சொல்லைக் கேட்க மாட்டார்கள்")
        if (CREDENTIAL_NEGATION_PATTERN.matcher(sentence).find()) {
            return CredentialIntent.WARNED_AGAINST;
        }

        // 2. Check if extraction action verb is used in the sentence
        if (EXTRACTION_REQUEST_PATTERN.matcher(sentence).find()) {
            return CredentialIntent.REQUESTED;
        }

        // 3. Otherwise merely mentioned
        return CredentialIntent.MENTIONED_ONLY;
    }
}
