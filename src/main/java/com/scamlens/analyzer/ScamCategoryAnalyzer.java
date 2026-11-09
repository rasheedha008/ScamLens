package com.scamlens.analyzer;

import com.scamlens.model.ScamIndicator;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ScamCategoryAnalyzer {

    private final ContextAnalyzer contextAnalyzer;
    private final MessageAnalyzer messageAnalyzer;

    public ScamCategoryAnalyzer(ContextAnalyzer contextAnalyzer, MessageAnalyzer messageAnalyzer) {
        this.contextAnalyzer = contextAnalyzer;
        this.messageAnalyzer = messageAnalyzer;
    }

    public static final String CAT_PHISHING = "Phishing";
    public static final String CAT_OTP_THEFT = "OTP and Credential Theft";
    public static final String CAT_FINANCIAL_FRAUD = "Financial Fraud";
    public static final String CAT_LOTTERY_SCAM = "Lottery and Prize Scams";
    public static final String CAT_FAKE_JOB = "Fake Job Scams";
    public static final String CAT_IMPERSONATION = "Impersonation";
    public static final String CAT_URGENCY_THREAT = "Urgency and Threat Scams";

    /**
     * Identifies all matching scam indicators across the 7 categories while respecting semantic context.
     */
    public List<ScamIndicator> detectIndicators(String text) {
        if (text == null || text.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<ScamIndicator> indicators = new ArrayList<>();
        List<String> sentences = messageAnalyzer.splitSentences(text);
        String lowerFull = text.toLowerCase();

        boolean isProtectiveMessage = contextAnalyzer.isProtectiveWarningMessage(text);

        // 1. Phishing analysis
        analyzePhishing(sentences, lowerFull, indicators, isProtectiveMessage);

        // 2. OTP and Credential Theft
        analyzeOtpAndCredentialTheft(sentences, lowerFull, indicators, isProtectiveMessage);

        // 3. Financial Fraud
        analyzeFinancialFraud(sentences, lowerFull, indicators, isProtectiveMessage);

        // 4. Lottery and Prize Scams
        analyzeLotteryScams(sentences, lowerFull, indicators, isProtectiveMessage);

        // 5. Fake Job Scams
        analyzeJobScams(sentences, lowerFull, indicators, isProtectiveMessage);

        // 6. Impersonation
        analyzeImpersonation(sentences, lowerFull, indicators, isProtectiveMessage);

        // 7. Urgency and Threat Scams
        analyzeUrgencyAndThreats(sentences, lowerFull, indicators, isProtectiveMessage);

        return indicators;
    }

    private void analyzePhishing(List<String> sentences, String fullText, List<ScamIndicator> indicators, boolean isProtective) {
        if (isProtective) return;

        Map<Pattern, PhishRule> rules = new LinkedHashMap<>();
        rules.put(
                Pattern.compile("\\b(verify|confirm|validate|update|re-?activate|restore|unlock|secure)\\s+(your\\s+)?(account|identity|details|credentials|profile|access|kyc|card|pan|security|banking)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("PHISH_VERIFY", "Account / Identity Verification Lure", 20, "Coerces the recipient into validating credentials or private identity data through unverified communication.")
        );
        rules.put(
                Pattern.compile("\\b(account|card|access|service|services|netbanking)\\s+(is|has\\s+been|will\\s+be)?\\s*(suspended|blocked|locked|disabled|deactivated|terminated|closed)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("PHISH_SUSPEND", "Account Suspension / Block Alert", 20, "Fabricates imminent account suspension or card blocking to bypass user scrutiny.")
        );
        rules.put(
                Pattern.compile("\\b(unauthorized|unusual|suspicious|illegal)\\s+(login|access|activity|attempts?|transaction)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("PHISH_UNUSUAL", "Fabricated Security Activity Alert", 20, "Alleges unauthorized login attempts or abnormal activity to panic recipient into following malicious instructions.")
        );
        rules.put(
                Pattern.compile("\\b(click\\s+(the\\s+link\\s+below\\s+to\\s+login|here\\s+to\\s+login|to\\s+login|to\\s+verify|below\\s+to\\s+login)|restore\\s+access|reactivate\\s+your\\s+account|fill\\s+out\\s+this\\s+form)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("PHISH_PORTAL", "Deceptive Login Redirection", 20, "Directs user to an external form or portal engineered to harvest authentication secrets.")
        );

        for (String sentence : sentences) {
            for (Map.Entry<Pattern, PhishRule> entry : rules.entrySet()) {
                Matcher m = entry.getKey().matcher(sentence);
                if (m.find()) {
                    String matched = m.group();
                    if (!contextAnalyzer.isKeywordNegated(sentence, matched)) {
                        PhishRule rule = entry.getValue();
                        addIndicatorIfAbsent(indicators, new ScamIndicator(
                                rule.code,
                                rule.name,
                                CAT_PHISHING,
                                rule.weight,
                                matched,
                                rule.explanation
                        ));
                    }
                }
            }
        }
    }

    private void analyzeOtpAndCredentialTheft(List<String> sentences, String fullText, List<ScamIndicator> indicators, boolean isProtective) {
        if (isProtective) return;

        Pattern harvestPattern = Pattern.compile(
                "\\b(share|send|provide|submit|reply\\s+with|enter|give|disclose|forward|verify)\\b.{0,40}\\b(otp|one[-\\s]?time\\s+password|pin|cvv|password|passcode|secret\\s+code|netbanking\\s+password|upi\\s+pin|atm\\s+pin|security\\s+code)\\b",
                Pattern.CASE_INSENSITIVE
        );

        Pattern mandatoryPattern = Pattern.compile(
                "\\b(otp|one[-\\s]?time\\s+password|pin|cvv|password)\\b.{0,30}\\b(required|needed|mandatory|to\\s+verify|to\\s+confirm|to\\s+cancel|to\\s+restore)\\b",
                Pattern.CASE_INSENSITIVE
        );

        String[] credentialKeywords = {"otp", "one-time password", "pin", "cvv", "password", "security code", "passcode", "atm pin", "upi pin"};

        for (String sentence : sentences) {
            String lower = sentence.toLowerCase();

            Matcher harvestMatcher = harvestPattern.matcher(sentence);
            if (harvestMatcher.find()) {
                String matched = harvestMatcher.group();
                if (!contextAnalyzer.isKeywordNegated(sentence, matched)) {
                    addIndicatorIfAbsent(indicators, new ScamIndicator(
                            "CRED_01",
                            "Direct Credential Solicitation",
                            CAT_OTP_THEFT,
                            30,
                            matched,
                            "Direct solicitation of private authentication secrets (" + matched + "), which legitimate financial institutions never request."
                    ));
                    continue;
                }
            }

            Matcher mandMatcher = mandatoryPattern.matcher(sentence);
            if (mandMatcher.find()) {
                String matched = mandMatcher.group();
                if (!contextAnalyzer.isKeywordNegated(sentence, matched)) {
                    addIndicatorIfAbsent(indicators, new ScamIndicator(
                            "CRED_02",
                            "Mandated Credential Requirement",
                            CAT_OTP_THEFT,
                            30,
                            matched,
                            "Demands entry or transmission of single-use security credentials under false pretexts."
                    ));
                    continue;
                }
            }

            for (String cred : credentialKeywords) {
                if (lower.contains(cred)) {
                    if (contextAnalyzer.isKeywordNegated(sentence, cred)) {
                        continue;
                    }
                    if (contextAnalyzer.hasActiveRequestIntent(sentence, cred) ||
                        lower.contains("send " + cred) || lower.contains("enter " + cred) || lower.contains("share " + cred)) {
                        addIndicatorIfAbsent(indicators, new ScamIndicator(
                                "CRED_03",
                                "Sensitive Credential Request",
                                CAT_OTP_THEFT,
                                30,
                                cred,
                                "Solicitation of private authentication code (" + cred.toUpperCase() + ")."
                        ));
                        break;
                    }
                }
            }
        }
    }

    private void analyzeFinancialFraud(List<String> sentences, String fullText, List<ScamIndicator> indicators, boolean isProtective) {
        if (isProtective) return;

        Map<Pattern, PhishRule> rules = new LinkedHashMap<>();
        rules.put(
                Pattern.compile("\\b(refundable|registration|processing|clearance|activation|transfer|verification)\\s+(fee|deposit|charges?|amount)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("FIN_FEE", "Advance Fee / Deposit Demand", 25, "Demands upfront registration or advance fee payment before services or supposed earnings are released.")
        );
        rules.put(
                Pattern.compile("\\b(pay|transfer|send|deposit)\\b.{0,30}\\b(fee|charges?|tax|deposit|amount|money|funds?|inr|rs|usd|\\$|via\\s+upi|to\\s+upi)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("FIN_PAY", "Unsolicited Payment Directive", 25, "Commands recipient to transfer money or pay funds via electronic channels.")
        );
        rules.put(
                Pattern.compile("\\b(crypto(currency)?\\s+investment|double\\s+(your\\s+)?money|guaranteed\\s+(returns?|profit|income|payout))\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("FIN_PONZI", "High-Yield / Ponzi Investment Promise", 25, "Guarantees unrealistic returns or doubler schemes commonly tied to fraudulent cryptocurrency fraud.")
        );
        rules.put(
                Pattern.compile("\\b(unauthorized\\s+transaction\\s+refund|claim\\s+(your\\s+)?refund|wire\\s+transfer)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("FIN_REFUND", "Fake Refund / Irreversible Wire Transfer", 20, "Lures recipient with imaginary debit refunds or irreversible transfer requests.")
        );

        for (String sentence : sentences) {
            for (Map.Entry<Pattern, PhishRule> entry : rules.entrySet()) {
                Matcher m = entry.getKey().matcher(sentence);
                if (m.find()) {
                    String matched = m.group();
                    if (!contextAnalyzer.isKeywordNegated(sentence, matched)) {
                        PhishRule rule = entry.getValue();
                        addIndicatorIfAbsent(indicators, new ScamIndicator(
                                rule.code,
                                rule.name,
                                CAT_FINANCIAL_FRAUD,
                                rule.weight,
                                matched,
                                rule.explanation
                        ));
                    }
                }
            }
        }
    }

    private void analyzeLotteryScams(List<String> sentences, String fullText, List<ScamIndicator> indicators, boolean isProtective) {
        if (isProtective) return;

        Map<Pattern, PhishRule> rules = new LinkedHashMap<>();
        rules.put(
                Pattern.compile("\\b(congratulations|selected|winner|winning)\\b.{0,35}\\b(lottery|prize|cash|lucky\\s+draw|reward|jackpot|won|giveaway|contest)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("LOTTO_WIN", "Unsolicited Prize / Lucky Draw Claim", 20, "Notification asserting recipient won an unentered contest, sweepstakes, or lucky draw.")
        );
        rules.put(
                Pattern.compile("\\b(you\\s+have\\s+won|cash\\s+prize|claim\\s+(your\\s+)?(prize|reward|winnings?|lottery|award))\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("LOTTO_CLAIM", "Prize Claim Urgency", 20, "Urges immediate claiming of a fictitious award before arbitrary expiration.")
        );

        for (String sentence : sentences) {
            for (Map.Entry<Pattern, PhishRule> entry : rules.entrySet()) {
                Matcher m = entry.getKey().matcher(sentence);
                if (m.find()) {
                    String matched = m.group();
                    if (!contextAnalyzer.isKeywordNegated(sentence, matched)) {
                        PhishRule rule = entry.getValue();
                        addIndicatorIfAbsent(indicators, new ScamIndicator(
                                rule.code,
                                rule.name,
                                CAT_LOTTERY_SCAM,
                                rule.weight,
                                matched,
                                rule.explanation
                        ));
                    }
                }
            }
        }
    }

    private void analyzeJobScams(List<String> sentences, String fullText, List<ScamIndicator> indicators, boolean isProtective) {
        if (isProtective) return;

        Map<Pattern, PhishRule> rules = new LinkedHashMap<>();
        rules.put(
                Pattern.compile("\\b(part[-\\s]?time|full[-\\s]?time|work\\s+from\\s+home|online\\s+job|job\\s+offer|guaranteed\\s+job)\\b.{0,40}\\b(job|work|earn|salary|income|hiring|opportunity|tasks?)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("JOB_OFFER", "Unsolicited Part-Time / Work From Home Offer", 20, "Unsolicited recruitment pitch promising exaggerated compensation for minimal effort.")
        );
        rules.put(
                Pattern.compile("\\bpart[-\\s]?time\\s+(online\\s+)?(job|work|opportunity)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("JOB_PARTTIME", "Part-Time Online Job Lure", 20, "Unsolicited part-time employment solicitation designed to engage victims.")
        );
        rules.put(
                Pattern.compile("\\bearn\\s+[0-9,]+\\s*(daily|per\\s+day|weekly|today|monthly|an\\s+hour|per\\s+hour)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("JOB_WAGE", "Exaggerated Daily / Hourly Wage Promise", 20, "Promises unrealistically high daily/hourly wages to entice targets into advance fee traps.")
        );
        rules.put(
                Pattern.compile("\\b(youtube|telegram|instagram|tiktok|google\\s+review)\\s+(like|review|rating|subscribe|task)s?\\b|\\bsimple\\s+(youtube\\s+like\\s+)?tasks?\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("JOB_TASK", "Task-Based Scam (Like / Review Tasks)", 20, "Classic task-based cyber scam promising payouts for trivial video likes or reviews.")
        );
        rules.put(
                Pattern.compile("\\b(registration|activation|training|refundable)\\s+(fee|deposit)\\b.{0,30}\\b(job|work|account|to\\s+activate)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("JOB_FEE", "Job Activation / Registration Fee", 25, "Demands upfront registration or deposit payment before releasing job assignments or wages.")
        );
        rules.put(
                Pattern.compile("\\b(interview|contact\\s+hr|reach\\s+hr)\\s+(on|via)\\s+(telegram|whatsapp)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("JOB_CHANNEL", "Unofficial Recruitment Communication Channel", 15, "Directs job communication to unverified messaging channels (Telegram/WhatsApp).")
        );

        for (String sentence : sentences) {
            for (Map.Entry<Pattern, PhishRule> entry : rules.entrySet()) {
                Matcher m = entry.getKey().matcher(sentence);
                if (m.find()) {
                    String matched = m.group();
                    if (!contextAnalyzer.isKeywordNegated(sentence, matched)) {
                        PhishRule rule = entry.getValue();
                        addIndicatorIfAbsent(indicators, new ScamIndicator(
                                rule.code,
                                rule.name,
                                CAT_FAKE_JOB,
                                rule.weight,
                                matched,
                                rule.explanation
                        ));
                    }
                }
            }
        }
    }

    private void analyzeImpersonation(List<String> sentences, String fullText, List<ScamIndicator> indicators, boolean isProtective) {
        if (isProtective) return;

        Map<Pattern, PhishRule> rules = new LinkedHashMap<>();
        rules.put(
                Pattern.compile("\\b(package|parcel)\\s+(delivery|on\\s+hold|pending|failed|delayed|stuck|undelivered|is\\s+pending)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("IMP_PARCEL", "Parcel / Package Delivery Impersonation", 15, "Impersonates postal or logistics delivery services claiming delivery failure or pending consignment.")
        );
        rules.put(
                Pattern.compile("\\bconfirm\\s+(your\\s+)?delivery\\s+address\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("IMP_ADDRESS", "Delivery Address Confirmation Phish", 15, "Prompts target to confirm delivery address on suspicious link to harvest address and card details.")
        );
        rules.put(
                Pattern.compile("\\b(fedex|dhl|ups|usps|postal|india\\s*post|blue\\s*dart)\\b.{0,30}\\b(package|parcel|delivery|tracking|hold|pending|portal)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("IMP_CARRIER", "Logistics Brand Impersonation", 15, "Directly mimics well-known shipping carriers to exploit delivery expectations.")
        );
        rules.put(
                Pattern.compile("\\b(bank\\s+alert|bank\\s+account|state\\s+bank|sbi|hdfc|icici|axis|chase|wells\\s*fargo|bank\\s+of\\s+america)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("IMP_BANK", "Financial Institution Brand Impersonation", 15, "Impersonates banking entity to induce immediate compliant panic.")
        );
        rules.put(
                Pattern.compile("\\b(income\\s+tax\\s+department(\\s+refund)?|customs\\s+clearance\\s+fee|amazon\\s+customer\\s+support|netflix\\s+subscription\\s+suspended|geek\\s+squad|microsoft\\s+support)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("IMP_BRAND", "Corporate / Authority Impersonation", 15, "Impersonates recognized corporate brand or national government authority.")
        );

        for (String sentence : sentences) {
            for (Map.Entry<Pattern, PhishRule> entry : rules.entrySet()) {
                Matcher m = entry.getKey().matcher(sentence);
                if (m.find()) {
                    String matched = m.group();
                    if (!contextAnalyzer.isKeywordNegated(sentence, matched)) {
                        PhishRule rule = entry.getValue();
                        addIndicatorIfAbsent(indicators, new ScamIndicator(
                                rule.code,
                                rule.name,
                                CAT_IMPERSONATION,
                                rule.weight,
                                matched,
                                rule.explanation
                        ));
                    }
                }
            }
        }
    }

    private void analyzeUrgencyAndThreats(List<String> sentences, String fullText, List<ScamIndicator> indicators, boolean isProtective) {
        if (isProtective) return;

        Map<Pattern, PhishRule> rules = new LinkedHashMap<>();
        rules.put(
                Pattern.compile("\\b(account|service|services|card|sim)\\s+will\\s+be\\s+(suspended|blocked|deactivated|terminated|closed|frozen)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("URG_BLOCK", "Service Termination / Account Freeze Threat", 15, "Manufactures intense fear of account closure or service termination to force hasty compliance.")
        );
        rules.put(
                Pattern.compile("\\bwithin\\s+(24|12|48|2|1)\\s*hours?\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("URG_DEADLINE", "Artificial Deadline Pressure", 10, "Imposes an artificial ticking deadline to provoke instinctive response before verification.")
        );
        rules.put(
                Pattern.compile("\\b(immediate\\s+action\\s+required|urgently|immediately|without\\s+delay|at\\s+once|final\\s+notice)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("URG_ACTION", "High Urgency Coercive Language", 10, "High-urgency language engineered to induce psychological stress and bypass critical thinking.")
        );
        rules.put(
                Pattern.compile("\\b(legal\\s+action\\s+will\\s+be\\s+taken|arrest\\s+warrant|police\\s+complaint|face\\s+legal\\s+consequences)\\b", Pattern.CASE_INSENSITIVE),
                new PhishRule("URG_LEGAL", "Legal Intimidation / Arrest Threat", 20, "Severe intimidation alleging pending criminal prosecution or arrest warrants.")
        );

        for (String sentence : sentences) {
            for (Map.Entry<Pattern, PhishRule> entry : rules.entrySet()) {
                Matcher m = entry.getKey().matcher(sentence);
                if (m.find()) {
                    String matched = m.group();
                    if (!contextAnalyzer.isKeywordNegated(sentence, matched)) {
                        PhishRule rule = entry.getValue();
                        addIndicatorIfAbsent(indicators, new ScamIndicator(
                                rule.code,
                                rule.name,
                                CAT_URGENCY_THREAT,
                                rule.weight,
                                matched,
                                rule.explanation
                        ));
                    }
                }
            }
        }
    }

    private void addIndicatorIfAbsent(List<ScamIndicator> list, ScamIndicator ind) {
        for (ScamIndicator existing : list) {
            if (existing.getCode().equals(ind.getCode()) &&
                existing.getMatchedPhrase().equalsIgnoreCase(ind.getMatchedPhrase())) {
                return;
            }
        }
        list.add(ind);
    }

    private static class PhishRule {
        final String code;
        final String name;
        final int weight;
        final String explanation;

        PhishRule(String code, String name, int weight, String explanation) {
            this.code = code;
            this.name = name;
            this.weight = weight;
            this.explanation = explanation;
        }
    }
}
