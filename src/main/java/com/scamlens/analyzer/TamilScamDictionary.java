package com.scamlens.analyzer;

import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Comprehensive Tamil cybersecurity lexicon, phrase mappings, and bilingual scam taxonomy.
 * Defines the 16 specialized Tamil scam categories, credential vocabulary, urgency cues,
 * and protective negation indicators.
 */
@Component
public class TamilScamDictionary {

    // 16 Tamil Scam Categories
    public static final String CAT_BANKING_FRAUD = "வங்கி மோசடி";
    public static final String CAT_OTP_THEFT = "OTP மோசடி";
    public static final String CAT_PASSWORD_THEFT = "கடவுச்சொல் திருட்டு";
    public static final String CAT_FAKE_JOB = "போலியான வேலை வாய்ப்பு";
    public static final String CAT_PRIZE_LOTTERY = "பரிசு மற்றும் லாட்டரி மோசடி";
    public static final String CAT_FAKE_LOAN = "போலியான கடன் சலுகைகள்";
    public static final String CAT_KYC_PHISHING = "KYC புதுப்பிப்பு மோசடி";
    public static final String CAT_ELECTRICITY_SCAM = "மின்சாரக் கட்டண மோசடி";
    public static final String CAT_GOVT_IMPERSONATION = "போலியான அரசு அறிவிப்புகள்";
    public static final String CAT_FAKE_SUPPORT = "போலியான வாடிக்கையாளர் சேவை";
    public static final String CAT_PAYMENT_SCAM = "பணப்பரிமாற்ற மோசடி";
    public static final String CAT_PHISHING_URL = "இணையதள இணைப்பு மோசடி";
    public static final String CAT_IDENTITY_THEFT = "தனிப்பட்ட தகவல் திருட்டு";
    public static final String CAT_FAKE_CONTEST = "போலியான பரிசுப் போட்டிகள்";
    public static final String CAT_INVESTMENT_SCAM = "முதலீட்டு மோசடி";
    public static final String CAT_THREAT_URGENCY = "மிரட்டல் மற்றும் அவசரச் செய்திகள்";
    public static final String CAT_SECURITY_ADVISORY = "சட்டபூர்வ பாதுகாப்பு எச்சரிக்கை";

    // English equivalents for the 16 categories
    private static final Map<String, String> CATEGORY_TA_TO_EN = new LinkedHashMap<>();
    private static final Map<String, String> EN_ALIAS_TO_TA = new LinkedHashMap<>();
    static {
        CATEGORY_TA_TO_EN.put(CAT_BANKING_FRAUD, "Banking Fraud");
        CATEGORY_TA_TO_EN.put(CAT_OTP_THEFT, "OTP Theft");
        CATEGORY_TA_TO_EN.put(CAT_PASSWORD_THEFT, "Password Theft");
        CATEGORY_TA_TO_EN.put(CAT_FAKE_JOB, "Fake Job Offers");
        CATEGORY_TA_TO_EN.put(CAT_PRIZE_LOTTERY, "Prize and Lottery Scams");
        CATEGORY_TA_TO_EN.put(CAT_FAKE_LOAN, "Fake Loan Offers");
        CATEGORY_TA_TO_EN.put(CAT_KYC_PHISHING, "KYC Phishing");
        CATEGORY_TA_TO_EN.put(CAT_ELECTRICITY_SCAM, "Electricity Payment Scams");
        CATEGORY_TA_TO_EN.put(CAT_GOVT_IMPERSONATION, "Government Impersonation");
        CATEGORY_TA_TO_EN.put(CAT_FAKE_SUPPORT, "Fake Customer Support");
        CATEGORY_TA_TO_EN.put(CAT_PAYMENT_SCAM, "Payment Scams");
        CATEGORY_TA_TO_EN.put(CAT_PHISHING_URL, "Phishing URLs");
        CATEGORY_TA_TO_EN.put(CAT_IDENTITY_THEFT, "Personal Information Theft");
        CATEGORY_TA_TO_EN.put(CAT_FAKE_CONTEST, "Fake Competitions");
        CATEGORY_TA_TO_EN.put(CAT_INVESTMENT_SCAM, "Investment Scams");
        CATEGORY_TA_TO_EN.put(CAT_THREAT_URGENCY, "Threat-based Scams");
        CATEGORY_TA_TO_EN.put(CAT_SECURITY_ADVISORY, "Legitimate Security Advisory");

        // Aliases for legacy English categories
        EN_ALIAS_TO_TA.put("phishing", CAT_PHISHING_URL);
        EN_ALIAS_TO_TA.put("otp and credential theft", CAT_OTP_THEFT);
        EN_ALIAS_TO_TA.put("financial fraud", CAT_PAYMENT_SCAM);
        EN_ALIAS_TO_TA.put("lottery and prize scams", CAT_PRIZE_LOTTERY);
        EN_ALIAS_TO_TA.put("fake job scams", CAT_FAKE_JOB);
        EN_ALIAS_TO_TA.put("impersonation", CAT_GOVT_IMPERSONATION);
        EN_ALIAS_TO_TA.put("urgency and threat scams", CAT_THREAT_URGENCY);
        EN_ALIAS_TO_TA.put("suspicious url", CAT_PHISHING_URL);
    }

    // Common Tamil scam phrases mapped to English translations
    private static final Map<String, String> PHRASE_GLOSSARY = new LinkedHashMap<>();
    static {
        PHRASE_GLOSSARY.put("உடனடியாக அனுப்பவும்", "Send immediately");
        PHRASE_GLOSSARY.put("உங்கள் கணக்கு முடக்கப்படும்", "Your account will be blocked");
        PHRASE_GLOSSARY.put("OTP எண்ணை வழங்கவும்", "Provide OTP");
        PHRASE_GLOSSARY.put("பணம் செலுத்தவும்", "Make payment");
        PHRASE_GLOSSARY.put("பரிசு வென்றுள்ளீர்கள்", "You have won a prize");
        PHRASE_GLOSSARY.put("இலவச பரிசு", "Free gift");
        PHRASE_GLOSSARY.put("உங்கள் விவரங்களை உள்ளிடவும்", "Enter your details");
        PHRASE_GLOSSARY.put("இணைப்பைத் திறக்கவும்", "Open the link");
        PHRASE_GLOSSARY.put("வங்கி விவரங்களைப் பகிரவும்", "Share bank details");
        PHRASE_GLOSSARY.put("கடவுச்சொல்லை உள்ளிடவும்", "Enter password");
        PHRASE_GLOSSARY.put("KYC புதுப்பிக்கவும்", "Update KYC");
        PHRASE_GLOSSARY.put("கணக்கு ரத்து செய்யப்படும்", "Account will be cancelled");
        PHRASE_GLOSSARY.put("வேலை உறுதி செய்ய கட்டணம்", "Fee to confirm employment");
        PHRASE_GLOSSARY.put("உடனடியாகப் பதிவு செய்யவும்", "Register immediately");
        PHRASE_GLOSSARY.put("உங்கள் அடையாளத்தைச் சரிபார்க்கவும்", "Verify your identity");
        PHRASE_GLOSSARY.put("மின் இணைப்பு துண்டிக்கப்படும்", "Power will be disconnected");
        PHRASE_GLOSSARY.put("முன் கட்டணம் செலுத்தவும்", "Pay advance fee");
        PHRASE_GLOSSARY.put("இன்றிரவு 9 மணிக்குள்", "By 9 PM tonight");
        PHRASE_GLOSSARY.put("சட்ட நடவடிக்கை எடுக்கப்படும்", "Legal action will be taken");
        PHRASE_GLOSSARY.put("கைது நடவடிக்கை", "Arrest action");
    }

    /**
     * Translates a Tamil category name to English.
     */
    public String getEnglishCategory(String tamilCat) {
        return toEnglishCategory(tamilCat);
    }

    public static String toEnglishCategory(String tamilCat) {
        if (tamilCat == null) return null;
        return CATEGORY_TA_TO_EN.getOrDefault(tamilCat, tamilCat);
    }

    /**
     * Translates an English category name to Tamil.
     */
    public String getTamilCategory(String englishCat) {
        return toTamilCategory(englishCat);
    }

    public static String toTamilCategory(String englishCat) {
        if (englishCat == null) return null;
        String clean = englishCat.trim().toLowerCase();
        if (EN_ALIAS_TO_TA.containsKey(clean)) {
            return EN_ALIAS_TO_TA.get(clean);
        }
        for (Map.Entry<String, String> entry : CATEGORY_TA_TO_EN.entrySet()) {
            if (entry.getValue().equalsIgnoreCase(englishCat.trim())) {
                return entry.getKey();
            }
        }
        return englishCat;
    }

    /**
     * Looks up English meaning for a recognized Tamil phrase.
     */
    public String getPhraseMeaning(String tamilPhrase) {
        for (Map.Entry<String, String> entry : PHRASE_GLOSSARY.entrySet()) {
            if (tamilPhrase.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return tamilPhrase;
    }

    public Map<String, String> getAllCategories() {
        return Collections.unmodifiableMap(CATEGORY_TA_TO_EN);
    }
}
