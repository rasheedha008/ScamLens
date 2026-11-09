package com.scamlens.service;

import com.scamlens.model.AnalysisResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
public class RecommendationService {

    /**
     * Generates tailored safety actions based on analysis results and threat categories in English.
     */
    public List<String> generateRecommendations(AnalysisResult result) {
        Set<String> recommendations = new LinkedHashSet<>();

        if (result.isWarningContext()) {
            recommendations.add("This message appears to be a legitimate fraud warning or security advisory.");
            recommendations.add("Keep these safety guidelines in mind when receiving unsolicited calls, texts, or emails.");
            recommendations.add("Never share confidential credentials even if pressured by someone claiming to be an authority.");
            return new ArrayList<>(recommendations);
        }

        int score = result.getRiskScore();
        List<String> categories = result.getCategories();
        boolean hasUrls = result.getUrlFindings() != null && !result.getUrlFindings().isEmpty();

        if (score >= 50) {
            recommendations.add("Do not click any embedded links, buttons, or downloadable attachments in this message.");
            recommendations.add("Do not reply or provide any personal, financial, or authentication information.");
        }

        if (categories.contains("OTP and Credential Theft") || categories.contains("OTP மோசடி") || categories.contains("கடவுச்சொல் திருட்டு")) {
            recommendations.add("Never share your One-Time Password (OTP), ATM PIN, CVV, or passwords. Legitimate banks and support teams will never ask for them.");
            recommendations.add("If you inadvertently shared confidential credentials, contact your financial institution immediately to freeze your cards and accounts.");
        }

        if (categories.contains("Phishing") || categories.contains("Impersonation") || categories.contains("வங்கி மோசடி") || categories.contains("KYC புதுப்பிப்பு மோசடி")) {
            recommendations.add("Verify account status independently by visiting the official website directly (type the URL manually) or calling the verified customer service number.");
            recommendations.add("Inspect the sender's actual email address or phone number for deceptive variations or spoofing.");
        }

        if (categories.contains("Financial Fraud") || categories.contains("பணப்பரிமாற்ற மோசடி") || categories.contains("போலியான கடன் சலுகைகள்")) {
            recommendations.add("Never send money, make deposits, or authorize wire transfers to claim prizes, refunds, or job equipment.");
            recommendations.add("Report fraudulent transaction demands to your national cybercrime reporting portal (e.g., cybercrime.gov.in or ic3.gov).");
        }

        if (categories.contains("Fake Job Scams") || categories.contains("போலியான வேலை வாய்ப்பு")) {
            recommendations.add("Legitimate employers never demand upfront registration fees, training charges, or security deposits.");
            recommendations.add("Verify job vacancies through the official company careers portal rather than third-party messaging apps.");
        }

        if (categories.contains("Lottery and Prize Scams") || categories.contains("பரிசு மற்றும் லாட்டரி மோசடி") || categories.contains("போலியான பரிசுப் போட்டிகள்")) {
            recommendations.add("Remember that you cannot win a lottery or raffle that you never entered or purchased tickets for.");
            recommendations.add("Any request to pay taxes or fees upfront to unlock winnings is an advance-fee fraud scam.");
        }

        if (categories.contains("Urgency and Threat Scams") || categories.contains("மிரட்டல் மற்றும் அவசரச் செய்திகள்") || categories.contains("மின்சாரக் கட்டண மோசடி")) {
            recommendations.add("Scammers manufacture false urgency (e.g., 'blocked in 24 hours') to bypass your critical evaluation. Pause and verify calmly.");
        }

        if (hasUrls) {
            recommendations.add("Avoid interacting with shortened or obfuscated links. Preview URLs using legitimate security tools before clicking.");
        }

        if (score < 25 && recommendations.isEmpty()) {
            recommendations.add("No immediate scam indicators were detected, but always exercise standard cybersecurity caution.");
            recommendations.add("Ensure sender authenticity and confirm unexpected requests through verified official channels.");
        }

        return new ArrayList<>(recommendations);
    }

    /**
     * Generates tailored safety actions in authentic Tamil language.
     */
    public List<String> generateRecommendationsTa(AnalysisResult result) {
        Set<String> recommendations = new LinkedHashSet<>();

        if (result.isWarningContext()) {
            recommendations.add("இச்செய்தி முறையான மோசடி எச்சரிக்கை அல்லது நிறுவன பாதுகாப்பு வழிகாட்டுதலாகும்.");
            recommendations.add("அங்கீகரிக்கப்படாத அழைப்புகள், குறுஞ்செய்திகள் வரும்போது இந்த பாதுகாப்பு விதிகளைப் பின்பற்றவும்.");
            recommendations.add("அதிகாரிகள் என்று கூறினாலும் உங்கள் ரகசிய கடவுச்சொற்களை யாரிடமும் ஒருபோதும் பகிராதீர்கள்.");
            return new ArrayList<>(recommendations);
        }

        int score = result.getRiskScore();
        List<String> categories = result.getCategories();
        List<String> categoriesTa = result.getCategoriesTa();
        boolean hasUrls = result.getUrlFindings() != null && !result.getUrlFindings().isEmpty();

        if (score >= 50) {
            recommendations.add("இச்செய்தியில் உள்ள எந்தவொரு இணைப்பையும் (Link) அல்லது பதிவிறக்கக் கோப்புகளையும் கிளிக் செய்ய வேண்டாம்.");
            recommendations.add("தனிப்பட்ட விவரங்கள், வங்கித் தகவல்கள் அல்லது கடவுச்சொற்களை அனுப்பவோ பகிரவோ வேண்டாம்.");
        }

        boolean hasOtpTheft = categories.contains("OTP and Credential Theft") || categoriesTa.contains("OTP மோசடி") || categoriesTa.contains("கடவுச்சொல் திருட்டு");
        if (hasOtpTheft) {
            recommendations.add("உங்கள் ஒருமுறை கடவுச்சொல் (OTP), ஏடிஎம் பின், அல்லது கடவுச்சொல்லை யாரிடமும் பகிர வேண்டாம். உண்மையான வங்கிகள் இவற்றை ஒருபோதும் கேட்காது.");
            recommendations.add("நீங்கள் தவறுதலாக ரகசிய விவரங்களை பகிர்ந்திருந்தால், உடனடியாக உங்கள் வங்கியைத் தொடர்பு கொண்டு கணக்கு மற்றும் அட்டைகளை முடக்கவும்.");
        }

        boolean hasBankingPhish = categories.contains("Phishing") || categories.contains("Impersonation") || categoriesTa.contains("வங்கி மோசடி") || categoriesTa.contains("KYC புதுப்பிப்பு மோசடி");
        if (hasBankingPhish) {
            recommendations.add("வங்கி கணக்கு அல்லது KYC நிலையை சரிபார்க்க அதிகாரப்பூர்வ வங்கி இணையதளத்தை நேரடியாக அணுகவும் அல்லது வாடிக்கையாளர் சேவை மையத்தை அழைக்கவும்.");
            recommendations.add("அனுப்புநரின் உண்மையான தொலைபேசி எண் அல்லது மின்னஞ்சலை கவனமாக சரிபார்க்கவும்.");
        }

        boolean hasPaymentFraud = categories.contains("Financial Fraud") || categoriesTa.contains("பணப்பரிமாற்ற மோசடி") || categoriesTa.contains("போலியான கடன் சலுகைகள்");
        if (hasPaymentFraud) {
            recommendations.add("கடன், பரிசு அல்லது ரீஃபண்ட் பெற எக்காரணம் கொண்டும் முன்பணம் அல்லது செயலாக்க கட்டணம் செலுத்த வேண்டாம்.");
            recommendations.add("மோசடி பணப்பரிவர்த்தனைகள் குறித்து தேசிய இணைய குற்றப் புகாரளிப்பு தளத்தில் (cybercrime.gov.in) புகார் அளிக்கவும்.");
        }

        boolean hasJobScam = categories.contains("Fake Job Scams") || categoriesTa.contains("போலியான வேலை வாய்ப்பு");
        if (hasJobScam) {
            recommendations.add("உண்மையான நிறுவனங்கள் வேலை வாய்ப்புக்காக முன்பதிவுக் கட்டணமோ அல்லது பயிற்சி கட்டணமோ ஒருபோதும் கோருவதில்லை.");
            recommendations.add("வேலை வாய்ப்புகளை நிறுவனத்தின் அதிகாரப்பூர்வ இணையதளம் மூலம் மட்டுமே உறுதிப்படுத்தவும்.");
        }

        boolean hasPrizeScam = categories.contains("Lottery and Prize Scams") || categoriesTa.contains("பரிசு மற்றும் லாட்டரி மோசடி") || categoriesTa.contains("போலியான பரிசுப் போட்டிகள்");
        if (hasPrizeScam) {
            recommendations.add("நீங்கள் பங்கேற்காத எந்தவொரு போட்டியிலும் அல்லது குலுக்கலிலும் பரிசு பெற முடியாது என்பதை நினைவில் கொள்ளுங்கள்.");
            recommendations.add("பரிசுத்தொகையைப் பெற வரி அல்லது கட்டணம் செலுத்தக் கோருவது முற்றிலும் ஏமாற்று வேலையாகும்.");
        }

        boolean hasElectricityScam = categoriesTa.contains("மின்சாரக் கட்டண மோசடி");
        if (hasElectricityScam) {
            recommendations.add("மின் கட்டண விபரங்களை அறிய மின்வாரியத்தின் (TNEB) அதிகாரப்பூர்வ இணையதளம் அல்லது மின்வாரிய அலுவலகத்தை நேரடியாக தொடர்பு கொள்ளவும்.");
        }

        boolean hasThreat = categories.contains("Urgency and Threat Scams") || categoriesTa.contains("மிரட்டல் மற்றும் அவசரச் செய்திகள்");
        if (hasThreat) {
            recommendations.add("பயமுறுத்தி யோசிக்க விடாமல் செய்வதே மோசடி செய்பவர்களின் உத்தி. அமைதியாக இருந்து உண்மையை சரிபார்க்கவும்.");
        }

        if (hasUrls) {
            recommendations.add("குறுக்கப்பட்ட அல்லது அறியப்படாத இணைப்புகளை (Shortened URLs) கிளிக் செய்வதைத் தவிர்க்கவும்.");
        }

        if (score < 25 && recommendations.isEmpty()) {
            recommendations.add("உடனடி மோசடி அச்சுறுத்தல்கள் ஏதும் கண்டறியப்படவில்லை, இருப்பினும் இணைய பாதுகாப்பில் எச்சரிக்கையாக இருக்கவும்.");
            recommendations.add("எதிர்பாராத கோரிக்கைகளை அதிகாரப்பூர்வ சேனல்கள் மூலம் எப்போதும் சரிபார்க்கவும்.");
        }

        return new ArrayList<>(recommendations);
    }
}
