package com.scamlens.analyzer;

import com.scamlens.model.ScamIndicator;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Core Tamil Semantic Scam Analyzer.
 * Evaluates sentence meaning, grammatical intent, and threat indicators across
 * all 16 specialized Tamil scam categories.
 */
@Component
public class TamilScamAnalyzer {

    private final TamilScamDictionary dictionary;
    private final TamilTextNormalizer normalizer;
    private final TamilNegationDetector negationDetector;
    private final TamilCredentialDetector credentialDetector;
    private final TamilActionDirectiveDetector directiveDetector;

    public TamilScamAnalyzer(TamilScamDictionary dictionary,
                             TamilTextNormalizer normalizer,
                             TamilNegationDetector negationDetector,
                             TamilCredentialDetector credentialDetector,
                             TamilActionDirectiveDetector directiveDetector) {
        this.dictionary = dictionary;
        this.normalizer = normalizer;
        this.negationDetector = negationDetector;
        this.credentialDetector = credentialDetector;
        this.directiveDetector = directiveDetector;
    }

    /**
     * Executes the comprehensive Tamil semantic inspection.
     */
    public List<ScamIndicator> analyze(String text) {
        if (text == null || text.trim().isEmpty()) {
            return Collections.emptyList();
        }

        String normalized = normalizer.normalize(text);
        List<String> sentences = normalizer.splitSentences(normalized);

        // 1. Detect credentials, directives, and negation context
        List<TamilCredentialDetector.CredentialMatch> allCreds = new ArrayList<>();
        List<TamilActionDirectiveDetector.ActionDirective> allDirectives = new ArrayList<>();

        for (String s : sentences) {
            allCreds.addAll(credentialDetector.detectCredentials(s));
            allDirectives.addAll(directiveDetector.detectDirectives(s));
        }

        TamilNegationDetector.TamilNegationEvaluation negationEval = negationDetector.evaluate(normalized, allCreds, allDirectives);
        boolean isWarning = negationEval.isProtectiveSafetyWarning();

        if (isWarning) {
            return Collections.emptyList();
        }

        List<ScamIndicator> indicators = new ArrayList<>();

        // 2. Analyze against 16 Tamil Scam Categories
        analyzeBankingFraud(sentences, normalized, indicators);
        analyzeOtpTheft(sentences, normalized, allCreds, indicators);
        analyzePasswordTheft(sentences, normalized, allCreds, indicators);
        analyzeFakeJobOffers(sentences, normalized, indicators);
        analyzePrizeAndLottery(sentences, normalized, indicators);
        analyzeFakeLoanOffers(sentences, normalized, indicators);
        analyzeKycPhishing(sentences, normalized, indicators);
        analyzeElectricityScams(sentences, normalized, indicators);
        analyzeGovtImpersonation(sentences, normalized, indicators);
        analyzeFakeCustomerSupport(sentences, normalized, indicators);
        analyzePaymentScams(sentences, normalized, indicators);
        analyzePhishingUrls(sentences, normalized, indicators);
        analyzePersonalIdentityTheft(sentences, normalized, indicators);
        analyzeFakeCompetitions(sentences, normalized, indicators);
        analyzeInvestmentScams(sentences, normalized, indicators);
        analyzeThreatsAndUrgency(sentences, normalized, indicators);

        return indicators;
    }

    // --- 1. வங்கி மோசடி (Banking Fraud) ---
    private void analyzeBankingFraud(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(வங்கி\\s+கணக்கு\\s+(முடக்கப்படும்|ரத்து|இடைநிறுத்தப்படும்|செயலிழக்கப்படும்)|வங்கி\\s+கணக்கு|இணைய\\s+வங்கி\\s+(முடக்கப்படும்|பிளாக்)|வங்கி\\s+விவரங்களை\\s+(பகிரவும்|வழங்கவும்|உள்ளிடவும்|அனுப்பவும்)|கணக்கு\\s+(முடக்கப்படும்|ரத்து\\s+செய்யப்படும்))",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_BANK_01", "வங்கி கணக்கு முடக்கம் / தகவல் கோரிக்கை", "Banking Account Freeze Threat / Details Request",
                TamilScamDictionary.CAT_BANKING_FRAUD, 25,
                "வங்கி கணக்கு முடக்கப்படும் என அச்சுறுத்தி அல்லது வங்கி விவரங்களை கோரும் மோசடி முறை.",
                "Threatens bank account suspension or solicits confidential banking credentials.", indicators);
    }

    // --- 2. OTP மோசடி (OTP Theft) ---
    private void analyzeOtpTheft(List<String> sentences, String fullText, List<TamilCredentialDetector.CredentialMatch> creds, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(உடனடியாக\\s+(உங்கள்\\s+)?otp|otp\\s+(எண்ணை\\s+)?(அனுப்பவும்|வழங்கவும்|உள்ளிடவும்|பகிரவும்)|சரிபார்க்க\\s+otp|otp-ஐ\\s+அனுப்பவும்|otp\\s+கோரப்படுகிறது|otp\\s+எண்ணை)",
                Pattern.CASE_INSENSITIVE
        );
        boolean matched = matchPattern(sentences, pattern, "TA_OTP_01", "OTP இரகசிய எண் கோரிக்கை", "Direct OTP Solicitation Directive",
                TamilScamDictionary.CAT_OTP_THEFT, 30,
                "ஒருமுறை கடவுச்சொல்லை (OTP) வழங்குமாறு நேரடியாக கோரும் கடுமையான மோசடி முறை.",
                "Direct solicitation commanding the recipient to disclose their One-Time Password (OTP).", indicators);

        boolean requestedOtp = creds.stream().anyMatch(c -> "OTP".equals(c.getEnglishName()) && c.getIntent() == TamilCredentialDetector.CredentialIntent.REQUESTED);
        if (!matched && requestedOtp) {
            indicators.add(new ScamIndicator(
                    "TA_OTP_01",
                    "Direct OTP Solicitation Directive",
                    "OTP இரகசிய எண் கோரிக்கை",
                    "OTP Theft",
                    TamilScamDictionary.CAT_OTP_THEFT,
                    30,
                    "OTP",
                    "Direct solicitation commanding recipient to disclose their OTP.",
                    "ஒருமுறை கடவுச்சொல்லை (OTP) வழங்குமாறு நேரடியாக கோரும் மோசடி."
            ));
        }
    }

    // --- 3. கடவுச்சொல் திருட்டு (Password Theft) ---
    private void analyzePasswordTheft(List<String> sentences, String fullText, List<TamilCredentialDetector.CredentialMatch> creds, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(கடவுச்சொல்லை\\s+(உள்ளிடவும்|மாற்றவும்|வழங்கவும்|அனுப்பவும்)|பாஸ்வேர்ட்\\s+உள்ளிடவும்|ரகசிய\\s+குறியீட்டை\\s+அனுப்பவும்|கடவுச்சொல்லை)",
                Pattern.CASE_INSENSITIVE
        );
        boolean matched = matchPattern(sentences, pattern, "TA_PWD_01", "கடவுச்சொல் பறிப்பு முயற்சி", "Confidential Password Solicitation",
                TamilScamDictionary.CAT_PASSWORD_THEFT, 30,
                "உங்கள் பாதுகாப்பான கடவுச்சொல்லை உள்ளிடவோ அல்லது அனுப்பவோ கோரும் முயற்சி.",
                "Unsolicited directive commanding user to disclose netbanking or login passwords.", indicators);

        boolean requestedPwd = creds.stream().anyMatch(c -> "Password".equals(c.getEnglishName()) && c.getIntent() == TamilCredentialDetector.CredentialIntent.REQUESTED);
        if (!matched && requestedPwd) {
            indicators.add(new ScamIndicator(
                    "TA_PWD_01",
                    "Confidential Password Solicitation",
                    "கடவுச்சொல் பறிப்பு முயற்சி",
                    "Password Theft",
                    TamilScamDictionary.CAT_PASSWORD_THEFT,
                    30,
                    "கடவுச்சொல்",
                    "Unsolicited directive commanding user to disclose login passwords.",
                    "உங்கள் கடவுச்சொல்லை உள்ளிடவோ அனுப்பவோ கோரும் முயற்சி."
            ));
        }
    }

    // --- 4. போலியான வேலை வாய்ப்பு (Fake Job Offers) ---
    private void analyzeFakeJobOffers(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(பகுதி\\s+நேர\\s+வேலை|வீட்டில்\\s+இருந்தே\\s+வேலை|தினசரி\\s+வருமானம்|யூடியூப்\\s+லைக்|வேலை\\s+உறுதி\\s+செய்ய\\s+கட்டணம்|வேலை\\s+வாய்ப்பு|பதிவு\\s+கட்டணம்)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_JOB_01", "போலி பகுதிநேர வேலை / முன் கட்டண மோசடி", "Fake Part-Time Job / Advance Fee Scheme",
                TamilScamDictionary.CAT_FAKE_JOB, 25,
                "குறைந்த உழைப்பில் அதிக தினசரி வருமானம் அல்லது வேலைக்காக முன்பணம் கோரும் போலி வேலை வாய்ப்பு.",
                "Lures victim with unrealistically high part-time task earnings requiring upfront activation fees.", indicators);
    }

    // --- 5. பரிசு மற்றும் லாட்டரி மோசடி (Prize and Lottery Scams) ---
    private void analyzePrizeAndLottery(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(பரிசு\\s+வென்றுள்ளீர்கள்|இலவச\\s+பரிசு|லாட்டரி\\s+வெற்றி|குலுக்கலில்|பரிசைப்\\s+பெற|ரொக்கப்\\s+பரிசு|பரிசு\\s+வென்று|லட்சம்\\s+பரிசு)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_PRIZE_01", "போலி லாட்டரி / பரிசு அறிவிப்பு", "Fake Lottery / Cash Prize Notification",
                TamilScamDictionary.CAT_PRIZE_LOTTERY, 20,
                "விண்ணப்பிக்காத போட்டியில் பரிசு வென்றுள்ளதாக கூறி கட்டணம் அல்லது விவரங்களை பறிக்கும் மோசடி.",
                "Notification asserting target won an unentered contest, demanding fees to release fictitious funds.", indicators);
    }

    // --- 6. போலியான கடன் சலுகைகள் (Fake Loan Offers) ---
    private void analyzeFakeLoanOffers(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(உடனடி\\s+கடன்|ஆவணங்கள்\\s+இன்றி\\s+கடன்|0%\\s+வட்டி\\s+கடன்|கடன்\\s+ஒப்புதல்|கடன்\\s+செயலாக்க\\s+கட்டணம்|குறைந்த\\s+வட்டியில்\\s+கடன்|கடன்\\s+சலுகை)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_LOAN_01", "போலி உடனடி கடன் / முன் கட்டண மோசடி", "Deceptive Instant Loan / Advance Clearance Scheme",
                TamilScamDictionary.CAT_FAKE_LOAN, 20,
                "ஆவணங்கள் இன்றி உடனடி கடன் தருவதாக கூறி முன் செயலாக்க கட்டணம் பறிக்கும் மோசடி.",
                "Deceptive zero-documentation instant loan promises demanding upfront processing fees.", indicators);
    }

    // --- 7. KYC புதுப்பிப்பு மோசடி (KYC Phishing) ---
    private void analyzeKycPhishing(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(kyc\\s+(விவரங்களைப்\\s+)?புதுப்பிக்கவும்|kyc\\s+காலாவதியானது|kyc\\s+புதுப்பிக்காவிட்டால்|ஆதார்\\s+(விவரங்களை|சரிபார்க்க)\\s+kyc|kyc\\s+முடக்கம்|kyc)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_KYC_01", "KYC புதுப்பிப்பு தூண்டில் மோசடி", "Coercive KYC Suspension Phishing",
                TamilScamDictionary.CAT_KYC_PHISHING, 25,
                "KYC காலாவதியானது என அச்சுறுத்தி ஆவணங்கள் மற்றும் ரகசிய எண்களை திருடும் தூண்டில் செய்தி.",
                "Coercive notification alleging expired KYC status to extract identity documents and credentials.", indicators);
    }

    // --- 8. மின்சாரக் கட்டண மோசடி (Electricity Payment Scams) ---
    private void analyzeElectricityScams(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(மின்சாரக்\\s+கட்டணம்|மின்\\s+இணைப்பு\\s+துண்டிக்கப்படும்|இன்றிரவு\\s+9\\s+மணிக்குள்|மின்\\s+வாரிய|மின்சாரம்\\s+நிறுத்தப்படும்|மின்\\s+இணைப்பு)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_ELEC_01", "மின்சாரக் கட்டண துண்டிப்பு மிரட்டல்", "Electricity Disconnection Threat Scheme",
                TamilScamDictionary.CAT_ELECTRICITY_SCAM, 25,
                "மின் கட்டணம் செலுத்தவில்லை எனில் இன்றிரவு மின் இணைப்பு துண்டிக்கப்படும் என மிரட்டும் ஏமாற்று வேலை.",
                "Fabricates imminent utility power disconnection to coerce immediate unverified payments.", indicators);
    }

    // --- 9. போலியான அரசு அறிவிப்புகள் (Government Impersonation) ---
    private void analyzeGovtImpersonation(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(அரசு\\s+இலவச\\s+(திட்டம்|நிதி|மடிக்கணினி|பணம்)|பிரதமர்\\s+நிவாரண|மத்திய\\s+அரசு|அரசு\\s+மானியம்|வருமான\\s+வரித்துறை)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_GOVT_01", "போலி அரசு மானிய அறிவிப்பு", "Government Agency Scheme Impersonation",
                TamilScamDictionary.CAT_GOVT_IMPERSONATION, 20,
                "அரசு இலவச நிதி அல்லது மானியம் தருவதாக போலியாக சித்தரிக்கும் ஏமாற்று செய்தி.",
                "Impersonates national or state government authorities offering fictitious grants or subsidies.", indicators);
    }

    // --- 10. போலியான வாடிக்கையாளர் சேவை (Fake Customer Support) ---
    private void analyzeFakeCustomerSupport(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(வாடிக்கையாளர்\\s+சேவைக்கு\\s+அழைக்கவும்|உதவி\\s+மையத்தை|உதவிக்கு\\s+அழைக்கவும்|கஸ்டமர்\\s+கேர்|உதவி\\s+எண்|தொடர்பு\\s+கொள்ளவும்:\\s*[0-9+]{8,})",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_SUPP_01", "போலி வாடிக்கையாளர் சேவை அழைப்பு", "Fake Customer Helpline / Vishing Lure",
                TamilScamDictionary.CAT_FAKE_SUPPORT, 15,
                "போலியான வாடிக்கையாளர் சேவை எண்ணை வழங்கி தொடர்பு கொள்ள தூண்டும் பொறி.",
                "Provides unverified helpline numbers to lure victims into fraudulent telephone social engineering.", indicators);
    }

    // --- 11. பணப்பரிமாற்ற மோசடி (Payment Scams) ---
    private void analyzePaymentScams(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(பணம்\\s+செலுத்தவும்|பணம்\\s+செலுத்தாவிட்டால்|கட்டணம்\\s+செலுத்தவும்|செலுத்தவும்|கூகுள்\\s+பே|போன்பே|யுபிஐ\\s+மூலம்|முன்பணம்\\s+அனுப்பவும்|ரீஃபண்ட்\\s+பெற\\s+பணம்)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_PAY_01", "அங்கீகரிக்கப்படாத பணப்பரிமாற்ற கட்டளை", "Unsolicited Electronic Payment Coercion",
                TamilScamDictionary.CAT_PAYMENT_SCAM, 25,
                "மின்னணு பரிமாற்றம் (UPI/GPay/PhonePe) மூலம் பணம் அனுப்புமாறு வற்புறுத்தும் கட்டளை.",
                "Commands target to transfer funds via UPI or payment apps under false pretexts.", indicators);
    }

    // --- 12. இணையதள இணைப்பு மோசடி (Phishing URLs in Tamil) ---
    private void analyzePhishingUrls(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(இணைப்பைத்\\s+திறக்கவும்|கீழே\\s+உள்ள\\s+லிங்கை|இணைப்பை\\s+கிளிக்\\s+செய்யவும்|லிங்க்\\s+வழியாக|லிங்கை|இணைப்பை)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_URL_01", "வெளிப்புற இணைய இணைப்பு தூண்டில்", "Suspicious External Link Redirection",
                TamilScamDictionary.CAT_PHISHING_URL, 15,
                "மின்னணு செய்தி வழியாக சந்தேகத்திற்கிடமான இணைப்பை திறக்க தூண்டும் முயற்சி.",
                "Directs recipient to open embedded unverified URLs to compromise credentials.", indicators);
    }

    // --- 13. தனிப்பட்ட தகவல் திருட்டு (Personal Information Theft) ---
    private void analyzePersonalIdentityTheft(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(உங்கள்\\s+தனிப்பட்ட\\s+(விவரங்களை|தகவல்களை)|விவரங்களை\\s+அனுப்பவும்|விவரங்களை\\s+உள்ளிடவும்|ஆதார்\\s+எண்ணை|படிவத்தை\\s+நிரப்பவும்|அடையாளத்தை\\s+சரிபார்க்கவும்|அடையாளத்தைச்\\s+சரிபார்க்கவும்)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_ID_01", "தனிப்பட்ட விவரங்களை பறிக்கும் தூண்டில்", "Personal Identity Harvest Solicitation",
                TamilScamDictionary.CAT_IDENTITY_THEFT, 20,
                "ஆதார், குடும்ப விவரங்கள் போன்ற தனிப்பட்ட அடையாள தகவல்களை பதிவு செய்ய தூண்டும் ஏமாற்று முறை.",
                "Prompts victim to disclose personal identifiers and identity documentation.", indicators);
    }

    // --- 14. போலியான பரிசுப் போட்டிகள் (Fake Competitions) ---
    private void analyzeFakeCompetitions(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(போட்டியில்\\s+வெற்றி|ஸ்பின்\\s+செய்து\\s+பரிசு|கேள்விக்கு\\s+பதிலளித்து\\s+பரிசு|சிறப்பு\\s+பரிசுப்\\s+போட்டி)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_COMP_01", "போலி பரிசுப் போட்டி தூண்டில்", "Fake Competition / Survey Scam Pattern",
                TamilScamDictionary.CAT_FAKE_CONTEST, 15,
                "போலி சக்கரம் சுழற்றுதல் அல்லது எளிய வினாக்களுக்கு பதிலளித்து பரிசு வெல்லலாம் என்ற தூண்டில்.",
                "Lures victims with fake interactive spins or quizzes to harvest personal details.", indicators);
    }

    // --- 15. முதலீட்டு மோசடி (Investment Scams) ---
    private void analyzeInvestmentScams(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(முதலீடு\\s+செய்து\\s+இரட்டிப்பு|குறைந்த\\s+முதலீட்டில்\\s+அதிக\\s+லாபம்|உத்தரவாத\\s+லாபம்|கிரிப்டோ\\s+முதலீடு|தினசரி\\s+10%\\s+லாபம்|பங்குச்சந்தை\\s+உறுதி|முதலீடு)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_INV_01", "போலி முதலீட்டு இரட்டிப்பு மோசடி", "High-Yield Ponzi Investment Scam",
                TamilScamDictionary.CAT_INVESTMENT_SCAM, 25,
                "உத்தரவாத லாபம் அல்லது பணத்தை இரட்டிப்பாக்குவதாக கூறி முதலீடு கோரும் ஏமாற்று முறை.",
                "Promises guaranteed unrealistic financial returns through fictitious investment schemes.", indicators);
    }

    // --- 16. மிரட்டல் மற்றும் அவசரச் செய்திகள் (Threat-based Scams) ---
    private void analyzeThreatsAndUrgency(List<String> sentences, String fullText, List<ScamIndicator> indicators) {
        Pattern pattern = Pattern.compile(
                "(உடனடியாக\\s+(உங்கள்|செய்யாவிட்டால்)|உடனடியாக|சட்ட\\s+நடவடிக்கை|காவல்துறை|கைது|24\\s+மணி\\s+நேரத்திற்குள்|இல்லையெனில்\\s+சேவை\\s+நிறுத்தப்படும்|அபராதம்|இன்றிரவு\\s+9\\s+மணிக்குள்|கடைசி\\s+எச்சரிக்கை|அவசர\\s+அறிவிப்பு|புறக்கணிக்க\\s+வேண்டாம்|புறக்கணிக்காதீர்|தாமதிக்க\\s+வேண்டாம்)",
                Pattern.CASE_INSENSITIVE
        );
        matchPattern(sentences, pattern, "TA_THREAT_01", "சட்ட அச்சுறுத்தல் மற்றும் அவசர மிரட்டல்", "Legal Coercion & Panic Induction Directive",
                TamilScamDictionary.CAT_THREAT_URGENCY, 20,
                "காவல்துறை, கைது அல்லது சேவை நிறுத்தம் என பயமுறுத்தி யோசிக்க விடாமல் செய்யும் மிரட்டல்.",
                "Fabricates legal consequences or imminent service suspension to induce panic and force compliance.", indicators);
    }

    private boolean matchPattern(List<String> sentences, Pattern pattern, String code, String nameTa, String nameEn,
                                 String catTa, int weight, String expTa, String expEn, List<ScamIndicator> indicators) {
        boolean matched = false;
        String catEn = dictionary.getEnglishCategory(catTa);

        for (String s : sentences) {
            Matcher m = pattern.matcher(s);
            if (m.find()) {
                String matchedPhrase = m.group();
                addIndicatorIfAbsent(indicators, new ScamIndicator(
                        code,
                        nameEn,
                        nameTa,
                        catEn,
                        catTa,
                        weight,
                        matchedPhrase,
                        expEn,
                        expTa
                ));
                matched = true;
            }
        }
        return matched;
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
}
