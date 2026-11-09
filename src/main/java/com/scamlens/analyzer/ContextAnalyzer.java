package com.scamlens.analyzer;

import com.scamlens.model.ContextEvaluation;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Innovation 1: Context-Aware Rule-Based Scam Detection Engine.
 * Analyzes semantic meaning, intent, negation, credential harvesting,
 * and suspicious action commands to differentiate legitimate advisories from real attacks.
 */
@Component
public class ContextAnalyzer {

    public static final String INTENT_LEGITIMATE_WARNING = "LEGITIMATE_WARNING";
    public static final String INTENT_ACTIVE_SCAM_REQUEST = "ACTIVE_SCAM_REQUEST";
    public static final String INTENT_SUSPICIOUS_DEMAND = "SUSPICIOUS_DEMAND";
    public static final String INTENT_BENIGN_COMMUNICATION = "BENIGN_COMMUNICATION";

    private static final List<String> NEGATION_PREFIXES = Arrays.asList(
            "never", "do not", "don't", "dont", "should not", "shouldn't",
            "must not", "will never", "would never", "under no circumstances",
            "caution", "beware of", "alert:", "warning:", "be aware",
            "fraud alert", "scam alert", "protect your", "advise you not to",
            "refrain from", "avoid sharing", "do not disclose", "never disclose",
            "never reveal", "do not enter", "never provide", "do not send",
            "strictly prohibited to share", "nobody from our bank will ask"
    );

    private static final List<String> WARNING_THEMES = Arrays.asList(
            "will never ask for", "never asks for", "never ask you for",
            "bank never asks", "we will never contact you to ask",
            "never share your otp", "do not share your password",
            "stay safe from fraud", "be cautious of unknown",
            "rbi cautions", "cyber crime alert", "security awareness",
            "protect yourself from scams", "keep your credentials secret",
            "fraud awareness initiative", "never share your pin"
    );

    private static final List<String> REQUEST_VERBS = Arrays.asList(
            "share your", "send your", "provide your", "enter your", "submit your",
            "reply with your", "verify your", "forward the", "input your",
            "confirm your", "update your", "disclose your", "give your",
            "click to verify", "claim your prize here", "pay processing fee"
    );

    private static final List<String> CREDENTIAL_KEYWORDS = Arrays.asList(
            "otp", "one time password", "password", "pin", "cvv",
            "card number", "atm pin", "netbanking password", "upi pin",
            "security code", "login credentials"
    );

    private static final List<String> URGENT_ACTION_DEMANDS = Arrays.asList(
            "immediately", "within 24 hours", "within 48 hours", "urgently", "without delay",
            "right now", "at once", "account will be blocked",
            "account will be suspended", "to avoid termination",
            "otherwise services will be stopped", "face legal consequences",
            "warrant issued", "electricity will be disconnected",
            "kyc suspended", "sim deactivated", "to activate your account",
            "confirm your delivery address", "unauthorized login", "restore access"
    );

    private static final Map<String, String> SUSPICIOUS_ACTION_PATTERNS = new LinkedHashMap<>();
    static {
        SUSPICIOUS_ACTION_PATTERNS.put("External Link Clicking", "(click\\s+(here|this\\s+link|below|the\\s+link|to|on)|follow\\s+this\\s+link|visit\\s+http|open\\s+(the\\s+)?link|confirm\\s+.*\\bnow:\\s*http)");
        SUSPICIOUS_ACTION_PATTERNS.put("Remote Desktop Access Command", "(download|install)\\s+(anydesk|teamviewer|quicksupport|rustdesk|remote)");
        SUSPICIOUS_ACTION_PATTERNS.put("Immediate Direct Calling", "(call\\s+(immediately|now|urgent|helpline|customer\\s+care)|dial\\s+[0-9+]{8,})");
        SUSPICIOUS_ACTION_PATTERNS.put("Credential Extraction Directive", "\\b(share|send|provide|submit|reply\\s+with|enter|give)\\b.{0,30}\\b(otp|pin|password|cvv|upi|credentials)\\b");
        SUSPICIOUS_ACTION_PATTERNS.put("Advance Payment / Transfer Demand", "\\b(pay|transfer|send|deposit)\\b.{0,30}\\b(amount|fee|fees|tax|charges?|money|rs|inr|\\$|funds?|deposit|upi)\\b");
        SUSPICIOUS_ACTION_PATTERNS.put("Unauthorized APK / App Installation", "\\b(install|download)\\b.{0,25}\\b(apk|attachment|software|application|app\\s+file|our\\s+app)\\b");
    }

    /**
     * Complete Context-Aware Intent Evaluation.
     * Evaluates message intent, negation signals, credential harvesting targets,
     * and suspicious action directives.
     */
    public ContextEvaluation evaluateContext(String text) {
        ContextEvaluation eval = new ContextEvaluation();
        if (text == null || text.trim().isEmpty()) {
            eval.setIntentType(INTENT_BENIGN_COMMUNICATION);
            eval.setIntentDescription("No textual content provided for intent evaluation.");
            return eval;
        }

        String lower = text.toLowerCase();

        // 1. Detect Negation Phrases
        List<String> detectedNegations = new ArrayList<>();
        for (String prefix : NEGATION_PREFIXES) {
            if (lower.contains(prefix)) {
                detectedNegations.add(prefix);
            }
        }
        for (String theme : WARNING_THEMES) {
            if (lower.contains(theme)) {
                detectedNegations.add(theme);
            }
        }
        eval.setNegationDetected(!detectedNegations.isEmpty());
        eval.setNegationPhrases(detectedNegations);

        // 2. Detect Requested Credentials
        List<String> requestedCreds = new ArrayList<>();
        for (String cred : CREDENTIAL_KEYWORDS) {
            if (lower.contains(cred)) {
                // Check if this credential keyword is actively requested vs negated
                if (hasActiveRequestIntent(text, cred)) {
                    requestedCreds.add(cred.toUpperCase());
                }
            }
        }
        eval.setRequestIntentDetected(!requestedCreds.isEmpty());
        eval.setRequestedCredentials(requestedCreds);

        // 3. Identify Suspicious Action Commands
        List<String> actions = identifySuspiciousActions(text);
        eval.setSuspiciousActionsIdentified(actions);

        // 4. Determine Protective Warning Advisory Status
        boolean isWarning = isProtectiveWarningMessage(text);
        eval.setWarningAdvisory(isWarning);

        // 5. Synthesize Final Intent Classification
        if (isWarning) {
            eval.setIntentType(INTENT_LEGITIMATE_WARNING);
            eval.setIntentDescription("Legitimate Institutional Security Advisory: The message educates users against disclosing credentials, utilizing explicit negation patterns (e.g. 'never share OTP', 'bank will not ask').");
        } else if (eval.isRequestIntentDetected() || (!actions.isEmpty() && hasUrgentActionDemand(text))) {
            eval.setIntentType(INTENT_ACTIVE_SCAM_REQUEST);
            eval.setIntentDescription("Active Scam Request Detected: The communication directly commands the recipient to provide sensitive data, make an urgent payment, or execute unverified actions under coercive pressure.");
        } else if (hasUrgentActionDemand(text) || !actions.isEmpty()) {
            eval.setIntentType(INTENT_SUSPICIOUS_DEMAND);
            eval.setIntentDescription("Suspicious Demand or Pressure Pattern: Contains urgent calls to action or intimidating consequences without explicitly mentioning credential harvest keywords.");
        } else {
            eval.setIntentType(INTENT_BENIGN_COMMUNICATION);
            eval.setIntentDescription("Benign Communication: No coercive pressure, credential extraction verbs, or malicious action directives detected.");
        }

        return eval;
    }

    /**
     * Identifies specific action commands embedded in the text.
     */
    public List<String> identifySuspiciousActions(String text) {
        List<String> actions = new ArrayList<>();
        if (text == null) {
            return actions;
        }

        for (Map.Entry<String, String> entry : SUSPICIOUS_ACTION_PATTERNS.entrySet()) {
            Pattern p = Pattern.compile(entry.getValue(), Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(text);
            if (m.find()) {
                // If it's credential extraction, ensure it's not negated
                if (entry.getKey().equals("Credential Extraction Directive")) {
                    if (!isProtectiveWarningMessage(text)) {
                        actions.add(entry.getKey() + " (Trigger: '" + m.group() + "')");
                    }
                } else {
                    actions.add(entry.getKey() + " (Trigger: '" + m.group() + "')");
                }
            }
        }
        return actions;
    }

    /**
     * Determines whether the given text is fundamentally an educational or institutional safety advisory.
     */
    public boolean isProtectiveWarningMessage(String text) {
        if (text == null) {
            return false;
        }
        String lower = text.toLowerCase();

        for (String theme : WARNING_THEMES) {
            if (lower.contains(theme)) {
                return true;
            }
        }

        boolean hasNegation = false;
        for (String neg : NEGATION_PREFIXES) {
            if (lower.contains(neg)) {
                hasNegation = true;
                break;
            }
        }

        boolean hasCredentialKeywords = lower.contains("otp") || lower.contains("password") ||
                                       lower.contains("pin") || lower.contains("cvv");

        boolean hasDirectRequest = false;
        for (String req : REQUEST_VERBS) {
            if (lower.contains(req) && !isKeywordNegated(text, req)) {
                hasDirectRequest = true;
                break;
            }
        }

        // If there's an active harvesting request for credentials, it's not a protective warning
        return hasNegation && hasCredentialKeywords && !hasDirectRequest;
    }

    /**
     * Checks if a specific keyword occurrence in a sentence is explicitly negated or warned against.
     */
    public boolean isKeywordNegated(String sentence, String keyword) {
        if (sentence == null || keyword == null) {
            return false;
        }
        String lowerSentence = sentence.toLowerCase();
        String lowerKeyword = keyword.toLowerCase();

        int keywordIndex = lowerSentence.indexOf(lowerKeyword);
        if (keywordIndex == -1) {
            return false;
        }

        for (String prefix : NEGATION_PREFIXES) {
            int prefixIndex = lowerSentence.indexOf(prefix);
            if (prefixIndex != -1 && prefixIndex < keywordIndex) {
                // Ensure the negation prefix occurs reasonably close (within 70 characters before the keyword)
                if (keywordIndex - prefixIndex < 70) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks if the sentence contains an active request / harvest intent for sensitive info.
     */
    public boolean hasActiveRequestIntent(String sentence, String keyword) {
        if (sentence == null || keyword == null) {
            return false;
        }
        String lowerSentence = sentence.toLowerCase();
        String lowerKeyword = keyword.toLowerCase();

        if (isKeywordNegated(sentence, keyword)) {
            return false;
        }

        for (String verb : REQUEST_VERBS) {
            if (lowerSentence.contains(verb)) {
                int verbIdx = lowerSentence.indexOf(verb);
                int keyIdx = lowerSentence.indexOf(lowerKeyword);
                if (keyIdx != -1 && Math.abs(keyIdx - verbIdx) < 80) {
                    return true;
                }
            }
        }

        Pattern reqPattern = Pattern.compile(
                "\\b(share|send|provide|enter|submit|reply with|verify|confirm)\\b.{0,40}\\b" + Pattern.quote(lowerKeyword) + "\\b",
                Pattern.CASE_INSENSITIVE
        );
        return reqPattern.matcher(lowerSentence).find();
    }

    /**
     * Checks if the message combines coercive urgency / threats with required actions.
     */
    public boolean hasUrgentActionDemand(String sentence) {
        if (sentence == null) {
            return false;
        }
        String lower = sentence.toLowerCase();
        for (String demand : URGENT_ACTION_DEMANDS) {
            if (lower.contains(demand)) {
                return true;
            }
        }
        return false;
    }
}
