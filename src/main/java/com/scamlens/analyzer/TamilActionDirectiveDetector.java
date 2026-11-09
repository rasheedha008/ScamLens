package com.scamlens.analyzer;

import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects Tamil action directives, identifying the requested command, target,
 * and contextual intent (coercive scam command vs benign vs safety negation).
 */
@Component
public class TamilActionDirectiveDetector {

    public static class ActionDirective {
        private final String actionVerb;
        private final String englishAction;
        private final String target;
        private final boolean isNegated;
        private final String rawClause;

        public ActionDirective(String actionVerb, String englishAction, String target, boolean isNegated, String rawClause) {
            this.actionVerb = actionVerb;
            this.englishAction = englishAction;
            this.target = target;
            this.isNegated = isNegated;
            this.rawClause = rawClause;
        }

        public String getActionVerb() {
            return actionVerb;
        }

        public String getEnglishAction() {
            return englishAction;
        }

        public String getTarget() {
            return target;
        }

        public boolean isNegated() {
            return isNegated;
        }

        public String getRawClause() {
            return rawClause;
        }

        @Override
        public String toString() {
            return englishAction + " (" + actionVerb + ")" + (isNegated ? " [NEGATED]" : "") + (target != null ? " Target: " + target : "");
        }
    }

    private static final Map<String, DirectiveRule> DIRECTIVE_RULES = new LinkedHashMap<>();
    static {
        DIRECTIVE_RULES.put("அனுப்பவும்", new DirectiveRule("அனுப்பவும்|அனுப்பவும்\\.|அனுப்புங்கள்", "Send", "Data / Message Transfer"));
        DIRECTIVE_RULES.put("வழங்கவும்", new DirectiveRule("வழங்கவும்|வழங்குங்கள்", "Provide", "Credential / Information Disclosure"));
        DIRECTIVE_RULES.put("உள்ளிடவும்", new DirectiveRule("உள்ளிடவும்|உள்ளிடுங்கள்", "Enter", "Credential Input"));
        DIRECTIVE_RULES.put("செலுத்தவும்", new DirectiveRule("செலுத்தவும்|செலுத்துங்கள்|செலுத்து", "Pay", "Payment Transfer"));
        DIRECTIVE_RULES.put("திறக்கவும்", new DirectiveRule("திறக்கவும்|திறங்கள்", "Open", "Link / App Opening"));
        DIRECTIVE_RULES.put("பதிவு செய்யவும்", new DirectiveRule("பதிவு\\s+செய்யவும்|பதிவு\\s+செய்யுங்கள்", "Register", "Registration"));
        DIRECTIVE_RULES.put("சரிபார்க்கவும்", new DirectiveRule("சரிபார்க்கவும்|சரிபாருங்கள்", "Verify", "Verification"));
        DIRECTIVE_RULES.put("பகிரவும்", new DirectiveRule("பகிரவும்|பகருங்கள்", "Share", "Credential Sharing"));
        DIRECTIVE_RULES.put("உறுதிப்படுத்தவும்", new DirectiveRule("உறுதிப்படுத்தவும்|உறுதிப்படுத்துங்கள்", "Confirm", "Confirmation"));
        DIRECTIVE_RULES.put("அழைக்கவும்", new DirectiveRule("அழைக்கவும்|அழையுங்கள்|தொடர்பு\\s+கொள்ளவும்", "Call / Contact", "Phone Callback"));
        DIRECTIVE_RULES.put("பதிவிறக்கவும்", new DirectiveRule("பதிவிறக்கவும்|பதிவிறக்கம்\\s+செய்யவும்|இன்ஸ்டால்\\s+செய்யவும்", "Download / Install", "Software / APK Installation"));
        DIRECTIVE_RULES.put("உடனே பதிலளிக்கவும்", new DirectiveRule("உடனே\\s+பதிலளிக்கவும்|பதிலளிக்கவும்", "Reply Immediately", "Immediate Response"));
        DIRECTIVE_RULES.put("கிளிக் செய்யவும்", new DirectiveRule("கிளிக்\\s+செய்யவும்|கிளிக்\\s+பண்ணவும்", "Click", "External Link Redirection"));
    }

    private static final Pattern NEGATION_SUFFIX_PATTERN = Pattern.compile("(வேண்டாம்|கூடாது|செய்யாதீர்கள்|மாட்டார்கள்)");

    /**
     * Extracts all Tamil action directives found in text.
     */
    public List<ActionDirective> detectDirectives(String text) {
        if (text == null || text.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<ActionDirective> directives = new ArrayList<>();

        for (Map.Entry<String, DirectiveRule> entry : DIRECTIVE_RULES.entrySet()) {
            String key = entry.getKey();
            DirectiveRule rule = entry.getValue();

            Pattern p = Pattern.compile("(?<![\\p{L}\\p{M}\\p{N}])(" + rule.patternRegex + ")(?![\\p{L}\\p{M}\\p{N}])", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS);
            Matcher m = p.matcher(text);

            while (m.find()) {
                String verb = m.group();
                int start = Math.max(0, m.start() - 30);
                int end = Math.min(text.length(), m.end() + 25);
                String clause = text.substring(start, end);

                boolean isNegated = NEGATION_SUFFIX_PATTERN.matcher(clause).find() ||
                        clause.contains(key + " வேண்டாம்") ||
                        clause.contains("பகிர வேண்டாம்") ||
                        clause.contains("அனுப்ப வேண்டாம்");

                String target = extractTarget(clause);
                directives.add(new ActionDirective(verb, rule.englishName, target, isNegated, clause));
            }
        }

        return directives;
    }

    private String extractTarget(String clause) {
        if (clause.contains("OTP") || clause.contains("ஓடிபி")) return "OTP";
        if (clause.contains("கடவுச்சொல்") || clause.contains("பாஸ்வேர்ட்")) return "Password";
        if (clause.contains("பணம்") || clause.contains("கட்டணம்")) return "Payment / Fee";
        if (clause.contains("இணைப்பு") || clause.contains("லிங்க்") || clause.contains("link")) return "URL / Link";
        if (clause.contains("விவரங்கள்") || clause.contains("தகவல்")) return "Personal Details";
        if (clause.contains("ஆப்") || clause.contains("apk") || clause.contains("செயலி")) return "App / APK";
        return null;
    }

    private static class DirectiveRule {
        final String patternRegex;
        final String englishName;
        final String defaultTarget;

        DirectiveRule(String patternRegex, String englishName, String defaultTarget) {
            this.patternRegex = patternRegex;
            this.englishName = englishName;
            this.defaultTarget = defaultTarget;
        }
    }
}
