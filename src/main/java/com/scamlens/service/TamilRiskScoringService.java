package com.scamlens.service;

import com.scamlens.analyzer.TamilScamDictionary;
import com.scamlens.model.ContextEvaluation;
import com.scamlens.model.ScamIndicator;
import com.scamlens.model.ScoreBreakdown;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Multilingual Risk Scoring Service for Tamil language analysis.
 * Calibrated so that equivalent scam scenarios in Tamil and English receive
 * comparable risk scores while respecting category caps and context-aware negation.
 */
@Service
public class TamilRiskScoringService {

    public static final String LEVEL_LOW = "Low";
    public static final String LEVEL_MEDIUM = "Medium";
    public static final String LEVEL_HIGH = "High";
    public static final String LEVEL_CRITICAL = "Critical";

    public static final String LEVEL_LOW_TA = "குறைந்த ஆபத்து";
    public static final String LEVEL_MEDIUM_TA = "நடுத்தர ஆபத்து";
    public static final String LEVEL_HIGH_TA = "அதிக ஆபத்து";
    public static final String LEVEL_CRITICAL_TA = "மிகக் கடுமையான ஆபத்து";

    private final TamilScamDictionary dictionary;

    public TamilRiskScoringService(TamilScamDictionary dictionary) {
        this.dictionary = dictionary;
    }

    private static final Map<String, Integer> CATEGORY_CAPS = new HashMap<>();
    static {
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_BANKING_FRAUD, 35);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_OTP_THEFT, 40);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_PASSWORD_THEFT, 40);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_FAKE_JOB, 35);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_PRIZE_LOTTERY, 30);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_FAKE_LOAN, 30);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_KYC_PHISHING, 35);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_ELECTRICITY_SCAM, 30);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_GOVT_IMPERSONATION, 25);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_FAKE_SUPPORT, 20);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_PAYMENT_SCAM, 35);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_PHISHING_URL, 35);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_IDENTITY_THEFT, 30);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_FAKE_CONTEST, 20);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_INVESTMENT_SCAM, 35);
        CATEGORY_CAPS.put(TamilScamDictionary.CAT_THREAT_URGENCY, 20);
        CATEGORY_CAPS.put("Suspicious URL", 35);
        CATEGORY_CAPS.put("Phishing", 35);
        CATEGORY_CAPS.put("OTP and Credential Theft", 40);
        CATEGORY_CAPS.put("Financial Fraud", 35);
        CATEGORY_CAPS.put("Fake Job Scams", 35);
        CATEGORY_CAPS.put("Lottery and Prize Scams", 30);
        CATEGORY_CAPS.put("Impersonation", 25);
        CATEGORY_CAPS.put("Urgency and Threat Scams", 20);
    }

    /**
     * Computes explainable score breakdown with bilingual details.
     */
    public ScoreBreakdown calculateBreakdown(List<ScamIndicator> indicators, ContextEvaluation contextEval, boolean hasExcessiveUrgency) {
        ScoreBreakdown breakdown = new ScoreBreakdown();
        boolean isWarning = contextEval != null && contextEval.isWarningAdvisory();

        int rawTotal = 0;
        Map<String, Integer> categorySums = new LinkedHashMap<>();
        List<ScoreBreakdown.IndicatorContribution> contributions = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        if (indicators != null) {
            for (ScamIndicator ind : indicators) {
                String dedupKey = ind.getCode() + "_" + ind.getMatchedPhrase();
                if (seen.contains(dedupKey)) {
                    continue;
                }
                seen.add(dedupKey);

                rawTotal += ind.getWeight();
                String cat = ind.getCategoryTa() != null ? ind.getCategoryTa() : ind.getCategory();
                categorySums.put(cat, categorySums.getOrDefault(cat, 0) + ind.getWeight());

                contributions.add(new ScoreBreakdown.IndicatorContribution(
                        ind.getCode(),
                        ind.getName(),
                        ind.getNameTa(),
                        ind.getCategory(),
                        ind.getCategoryTa(),
                        ind.getWeight(),
                        ind.getMatchedPhrase(),
                        ind.getExplanation(),
                        ind.getExplanationTa()
                ));
            }
        }

        if (hasExcessiveUrgency) {
            rawTotal += 5;
            contributions.add(new ScoreBreakdown.IndicatorContribution(
                    "TA_URG_PUNCT",
                    "Excessive Urgency & Punctuation",
                    "அதிகரித்த அவசரம் மற்றும் நிறுத்தக்குறிகள்",
                    "Urgency and Threat Scams",
                    TamilScamDictionary.CAT_THREAT_URGENCY,
                    5,
                    "! / ?",
                    "Punctuation signals panic induction to bypass critical thinking.",
                    "பதற்றத்தை உருவாக்கி உடனடியாக செயல்பட வைக்கும் நோக்கம்."
            ));
        }

        breakdown.setRawTotalScore(rawTotal);
        breakdown.setContributions(contributions);

        // Category Caps
        List<String> capsEn = new ArrayList<>();
        List<String> capsTa = new ArrayList<>();
        int cappedScore = 0;

        for (Map.Entry<String, Integer> entry : categorySums.entrySet()) {
            String cat = entry.getKey();
            int sum = entry.getValue();
            int maxCap = CATEGORY_CAPS.getOrDefault(cat, 35);

            if (sum > maxCap) {
                capsEn.add(cat + " capped at " + maxCap + " points (accumulated: " + sum + ")");
                capsTa.add(cat + " அதிகபட்ச வரம்பு: " + maxCap + " புள்ளிகள் (மொத்தம்: " + sum + ")");
                cappedScore += maxCap;
            } else {
                cappedScore += sum;
            }
        }

        if (hasExcessiveUrgency) {
            cappedScore += 5;
        }

        breakdown.setCategoryCapsApplied(capsEn);
        breakdown.setCategoryCapsAppliedTa(capsTa);

        // Context Adjustment
        int finalScore;
        if (isWarning) {
            finalScore = 5;
            breakdown.setContextAdjustment("Tamil Context-Aware Negation Discount: Genuine safety advisory identified. Risk reduced to baseline safe score (5/100).");
            breakdown.setContextAdjustmentTa("பாதுகாப்பு விழிப்புணர்வு அறிவிப்பு: ரகசிய தகவல்களை பகிர வேண்டாம் என எச்சரிப்பதால் மிகக் குறைந்த ஆபத்தாக (5/100) மதிப்பிடப்பட்டுள்ளது.");
        } else {
            finalScore = Math.max(0, Math.min(100, cappedScore));
            if (contextEval != null && "ACTIVE_SCAM_REQUEST".equals(contextEval.getIntentType())) {
                breakdown.setContextAdjustment("Active Tamil Scam Request / Direct Command detected: Full threat weights enforced.");
                breakdown.setContextAdjustmentTa("நேரடி மோசடி கட்டளை கண்டறியப்பட்டது: முழுமையான அச்சுறுத்தல் புள்ளிகள் பயன்படுத்தப்பட்டுள்ளன.");
            } else if (contextEval != null && "SUSPICIOUS_DEMAND".equals(contextEval.getIntentType())) {
                breakdown.setContextAdjustment("Suspicious Coercive Demand detected in Tamil script.");
                breakdown.setContextAdjustmentTa("சந்தேகத்திற்கிடமான அவசர கட்டளை கண்டறியப்பட்டது.");
            } else {
                breakdown.setContextAdjustment("Standard rule-based Tamil multi-indicator evaluation.");
                breakdown.setContextAdjustmentTa("நிலையான தமிழ் அச்சுறுத்தல் பகுப்பாய்வு.");
            }
        }

        breakdown.setFinalScore(finalScore);
        String level = determineRiskLevel(finalScore);
        breakdown.setRiskLevel(level);
        breakdown.setLevelExplanation(getRiskLevelExplanation(level, finalScore, isWarning, false));
        breakdown.setLevelExplanationTa(getRiskLevelExplanation(level, finalScore, isWarning, true));

        return breakdown;
    }

    public String determineRiskLevel(int score) {
        if (score >= 75) return LEVEL_CRITICAL;
        if (score >= 50) return LEVEL_HIGH;
        if (score >= 25) return LEVEL_MEDIUM;
        return LEVEL_LOW;
    }

    public String getRiskLevelExplanation(String level, int score, boolean isWarning, boolean inTamil) {
        if (inTamil) {
            if (isWarning) {
                return "குறைந்த ஆபத்து (" + score + "/100): இச்செய்தி அங்கீகரிக்கப்பட்ட விழிப்புணர்வு அல்லது நிறுவன எச்சரிக்கை அறிவிப்பாகும்.";
            }
            switch (level) {
                case LEVEL_CRITICAL:
                    return "மிகக் கடுமையான ஆபத்து (" + score + "/100): அதிக ஆபத்துள்ள மோசடி செய்தி. OTP, கடவுச்சொல் அல்லது நிதி இழப்பு அபாயம் உள்ளது.";
                case LEVEL_HIGH:
                    return "அதிக ஆபத்து (" + score + "/100): சந்தேகத்திற்குரிய இணைப்புகள், முன்பண கோரிக்கைகள் அல்லது கணக்கு முடக்க மிரட்டல்கள் உள்ளன.";
                case LEVEL_MEDIUM:
                    return "நடுத்தர ஆபத்து (" + score + "/100): அவசர சொற்கள் அல்லது சரிபார்க்கப்படாத சலுகைகள் உள்ளன. எச்சரிக்கை தேவை.";
                default:
                    return "குறைந்த ஆபத்து (" + score + "/100): அச்சுறுத்தல் கூறுகள் ஏதும் கண்டறியப்படவில்லை. பாதுகாப்பான செய்தி.";
            }
        } else {
            if (isWarning) {
                return "Low Risk (" + score + "/100): This Tamil message is an authentic safety advisory warning against disclosing credentials.";
            }
            switch (level) {
                case LEVEL_CRITICAL:
                    return "Critical Risk (" + score + "/100): High-confidence Tamil attack detected. Extreme danger of financial or credential theft.";
                case LEVEL_HIGH:
                    return "High Risk (" + score + "/100): Strong deception indicators in Tamil text (coercive threats, suspicious link or advance payment).";
                case LEVEL_MEDIUM:
                    return "Medium Risk (" + score + "/100): Caution advised. Suspicious urgency or unverified promotional claims identified.";
                default:
                    return "Low Risk (" + score + "/100): Minimal or no threat patterns detected in Tamil message.";
            }
        }
    }
}
