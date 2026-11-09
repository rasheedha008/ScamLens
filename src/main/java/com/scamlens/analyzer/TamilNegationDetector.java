package com.scamlens.analyzer;

import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Context-aware Tamil Negation Detector.
 * Differentiates protective institutional safety advisories (e.g., "OTP பகிர வேண்டாம்")
 * from manipulative urgency negation (e.g., "புறக்கணிக்க வேண்டாம், உங்கள் OTP உள்ளிடவும்").
 */
@Component
public class TamilNegationDetector {

    public static class TamilNegationEvaluation {
        private final boolean containsNegation;
        private final boolean isProtectiveSafetyWarning;
        private final List<String> detectedNegationTokens;
        private final String negationScopeExplanation;

        public TamilNegationEvaluation(boolean containsNegation, boolean isProtectiveSafetyWarning, List<String> detectedNegationTokens, String negationScopeExplanation) {
            this.containsNegation = containsNegation;
            this.isProtectiveSafetyWarning = isProtectiveSafetyWarning;
            this.detectedNegationTokens = detectedNegationTokens;
            this.negationScopeExplanation = negationScopeExplanation;
        }

        public boolean isContainsNegation() {
            return containsNegation;
        }

        public boolean isProtectiveSafetyWarning() {
            return isProtectiveSafetyWarning;
        }

        public List<String> getDetectedNegationTokens() {
            return detectedNegationTokens;
        }

        public String getNegationScopeExplanation() {
            return negationScopeExplanation;
        }
    }

    // Explicit protective negation patterns that safeguard credentials
    private static final List<String> PROTECTIVE_CREDENTIAL_NEGATIONS = Arrays.asList(
            "பகிர வேண்டாம்", "பகிரவேண்டாம்", "அனுப்ப வேண்டாம்", "வழங்க வேண்டாம்",
            "கேட்க மாட்டார்கள்", "கேட்காது", "தெரிவிக்க வேண்டாம்", "சொல்ல வேண்டாம்",
            "உள்ளிட வேண்டாம்", "நம்பாதீர்கள்", "திறக்க வேண்டாம்", "கிளிக் செய்ய வேண்டாம்",
            "செய்யாதீர்கள்", "பகிரக் கூடாது", "பகிரக்கூடாது", "அனுப்பக் கூடாது",
            "யாரிடமும் சொல்ல வேண்டாம்", "ஒருபோதும் கேட்க மாட்டார்கள்", "விழிப்புணர்வு எச்சரிக்கை",
            "பாதுகாப்பு விழிப்புணர்வு", "எச்சரிக்கை செய்தி"
    );

    // Manipulative negation patterns that urge compliance by saying "do not ignore / do not delay"
    private static final List<String> MANIPULATIVE_URGENCY_NEGATIONS = Arrays.asList(
            "புறக்கணிக்க வேண்டாம்", "புறக்கணிக்காதீர்", "தாமதிக்க வேண்டாம்", "தாமதிக்காதீர்",
            "மறக்க வேண்டாம்", "மறக்காதீர்", "பயப்பட வேண்டாம்", "கவலைப்பட வேண்டாம்"
    );

    // General negation words in Tamil
    private static final List<String> GENERAL_NEGATION_WORDS = Arrays.asList(
            "வேண்டாம்", "கூடாது", "செய்யாதீர்கள்", "மாட்டார்கள்", "இல்லை", "நம்பாதீர்கள்"
    );

    // Active credential extraction imperatives that override manipulative negation
    private static final Pattern ACTIVE_EXTRACTION_COMMAND = Pattern.compile(
            "(உள்ளிடவும்|அனுப்பவும்|வழங்கவும்|செலுத்தவும்|பதிவிடவும்|உறுதிப்படுத்தவும்|சரிபார்க்கவும்|கிளிக்\\s+செய்யவும்|திறக்கவும்|வங்கி\\s+விவரங்களை|otp\\s+எண்ணை|கடவுச்சொல்லை)\\s+(உள்ளிட|அனுப்ப|வழங்க|செலுத்த|சரிபார்க்க)"
    );

    /**
     * Evaluates Tamil negation context to decide whether it represents a genuine institutional
     * safety warning or deceptive urgency/active demand.
     */
    public TamilNegationEvaluation evaluate(String text, List<TamilCredentialDetector.CredentialMatch> credentials, List<TamilActionDirectiveDetector.ActionDirective> directives) {
        if (text == null || text.trim().isEmpty()) {
            return new TamilNegationEvaluation(false, false, Collections.emptyList(), "No text content for negation evaluation.");
        }

        List<String> detectedTokens = new ArrayList<>();
        boolean hasProtectiveNegation = false;
        boolean hasManipulativeNegation = false;

        // 1. Check Protective Negation Patterns
        for (String pat : PROTECTIVE_CREDENTIAL_NEGATIONS) {
            if (text.contains(pat)) {
                hasProtectiveNegation = true;
                detectedTokens.add(pat);
            }
        }

        // 2. Check Manipulative Negations (e.g. "புறக்கணிக்க வேண்டாம்" - do not ignore)
        for (String pat : MANIPULATIVE_URGENCY_NEGATIONS) {
            if (text.contains(pat)) {
                hasManipulativeNegation = true;
                detectedTokens.add(pat);
            }
        }

        // 3. Fallback general check
        if (detectedTokens.isEmpty()) {
            for (String gen : GENERAL_NEGATION_WORDS) {
                if (text.contains(gen)) {
                    detectedTokens.add(gen);
                }
            }
        }

        boolean containsNegation = !detectedTokens.isEmpty();

        // 4. Scope Resolution:
        // Case A: Contains manipulative negation ("புறக்கணிக்க வேண்டாம்"), but also has active extraction commands:
        // Example: "இந்த அறிவிப்பைப் புறக்கணிக்க வேண்டாம். உங்கள் OTP எண்ணை உள்ளிடவும்."
        boolean hasActiveExtraction = directives.stream().anyMatch(d -> !d.isNegated() && ("Enter".equals(d.getEnglishAction()) || "Send".equals(d.getEnglishAction()) || "Provide".equals(d.getEnglishAction()) || "Pay".equals(d.getEnglishAction())));
        boolean hasActiveCredentialRequest = credentials.stream().anyMatch(c -> c.getIntent() == TamilCredentialDetector.CredentialIntent.REQUESTED);

        if (hasManipulativeNegation && (hasActiveExtraction || hasActiveCredentialRequest)) {
            return new TamilNegationEvaluation(
                    containsNegation,
                    false, // NOT a safety warning! It's a scam message using manipulative urgency negation.
                    detectedTokens,
                    "Manipulative Urgency Negation: Contains phrasing like 'புறக்கணிக்க வேண்டாம்' (do not ignore), but actively commands credential entry or payment."
            );
        }

        // Case B: Explicit protective safety warning advising against credential disclosure:
        // Example: "உங்கள் OTP எண்ணை யாரிடமும் பகிர வேண்டாம்." or "வங்கி அதிகாரிகள் உங்கள் கடவுச்சொல்லைக் கேட்க மாட்டார்கள்."
        boolean hasWarnedCredentials = credentials.stream().anyMatch(c -> c.getIntent() == TamilCredentialDetector.CredentialIntent.WARNED_AGAINST);

        if (hasProtectiveNegation || hasWarnedCredentials) {
            return new TamilNegationEvaluation(
                    true,
                    true, // Legitimate safety warning!
                    detectedTokens,
                    "Legitimate Institutional Safety Advisory: Negation explicitly protects user credentials (e.g., 'பகிர வேண்டாம்', 'கேட்க மாட்டார்கள்')."
            );
        }

        return new TamilNegationEvaluation(
                containsNegation,
                false,
                detectedTokens,
                containsNegation ? "Negation detected but does not apply to credential safeguarding." : "No negation phrases identified."
        );
    }
}
