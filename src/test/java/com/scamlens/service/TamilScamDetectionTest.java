package com.scamlens.service;

import com.scamlens.analyzer.*;
import com.scamlens.model.AnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TamilScamDetectionTest {

    private ScamDetectionService detectionService;

    @BeforeEach
    void setUp() {
        MessageAnalyzer messageAnalyzer = new MessageAnalyzer();
        ContextAnalyzer contextAnalyzer = new ContextAnalyzer();
        UrlAnalyzer urlAnalyzer = new UrlAnalyzer();
        ScamCategoryAnalyzer categoryAnalyzer = new ScamCategoryAnalyzer(contextAnalyzer, messageAnalyzer);
        UrlAnalysisService urlAnalysisService = new UrlAnalysisService(urlAnalyzer);
        RiskScoringService riskScoringService = new RiskScoringService();
        RecommendationService recommendationService = new RecommendationService();

        TamilLanguageDetectionService langService = new TamilLanguageDetectionService();
        TamilTextNormalizer normalizer = new TamilTextNormalizer();
        TamilScamDictionary dictionary = new TamilScamDictionary();
        TamilNegationDetector negationDetector = new TamilNegationDetector();
        TamilCredentialDetector credentialDetector = new TamilCredentialDetector();
        TamilActionDirectiveDetector directiveDetector = new TamilActionDirectiveDetector();
        TamilScamAnalyzer scamAnalyzer = new TamilScamAnalyzer(dictionary, normalizer, negationDetector, credentialDetector, directiveDetector);
        TamilRiskScoringService riskService = new TamilRiskScoringService(dictionary);

        detectionService = new ScamDetectionService(
                messageAnalyzer,
                contextAnalyzer,
                categoryAnalyzer,
                urlAnalysisService,
                riskScoringService,
                recommendationService,
                langService,
                normalizer,
                dictionary,
                negationDetector,
                credentialDetector,
                directiveDetector,
                scamAnalyzer,
                riskService
        );
    }

    @Test
    @DisplayName("Tamil Banking Phishing: உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனடியாக விவரங்களை அனுப்பவும்.")
    void testTamilBankingPhishing() {
        String msg = "உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனடியாக உங்கள் வங்கி விவரங்களை அனுப்பவும்.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil Bank Scam Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.getRiskScore() >= 50);
        assertEquals("Tamil", result.getDetectedLanguage());
        assertTrue(result.getCategoriesTa().contains("வங்கி மோசடி"));
        assertFalse(result.getExplanationsTa().isEmpty());
    }

    @Test
    @DisplayName("Tamil OTP Theft: உடனடியாக உங்கள் OTP எண்ணை அனுப்பவும்.")
    void testTamilOtpTheft() {
        String msg = "உங்கள் வங்கி பரிவர்த்தனை நிலுவையில் உள்ளது. உடனடியாக உங்கள் OTP எண்ணை அனுப்பவும்.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil OTP Theft Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.getRiskScore() >= 50);
        assertTrue(result.getCategoriesTa().contains("OTP மோசடி"));
        assertTrue(result.getCredentialTargets().stream().anyMatch(c -> c.contains("OTP")));
    }

    @Test
    @DisplayName("Tamil Safety Warning 1: உங்கள் OTP எண்ணை யாரிடமும் பகிர வேண்டாம்.")
    void testTamilSafetyWarningOtp() {
        String msg = "வங்கி பாதுகாப்பு எச்சரிக்கை: உங்கள் OTP எண்ணை யாரிடமும் பகிர வேண்டாம்.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil Warning 1 Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.isWarningContext());
        assertEquals(5, result.getRiskScore());
        assertEquals(RiskScoringService.LEVEL_LOW, result.getRiskLevel());
        assertTrue(result.getCategoriesTa().contains(TamilScamDictionary.CAT_SECURITY_ADVISORY));
    }

    @Test
    @DisplayName("Tamil Safety Warning 2: வங்கி அதிகாரிகள் உங்கள் கடவுச்சொல்லைக் கேட்க மாட்டார்கள்.")
    void testTamilSafetyWarningPassword() {
        String msg = "விழிப்புணர்வு செய்தி: வங்கி அதிகாரிகள் உங்கள் கடவுச்சொல்லைக் கேட்க மாட்டார்கள். ரகசிய விவரங்களை பாதுகாப்பாக வைக்கவும்.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil Warning 2 Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.isWarningContext());
        assertEquals(5, result.getRiskScore());
        assertEquals(RiskScoringService.LEVEL_LOW, result.getRiskLevel());
    }

    @Test
    @DisplayName("Tamil Manipulative Negation: இந்த அறிவிப்பைப் புறக்கணிக்க வேண்டாம். உங்கள் OTP எண்ணை உள்ளிடவும்.")
    void testTamilManipulativeNegation() {
        String msg = "இந்த அறிவிப்பைப் புறக்கணிக்க வேண்டாம். உங்கள் OTP எண்ணை உள்ளிடவும்.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil Manipulative Negation Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertFalse(result.isWarningContext(), "Should NOT be classified as safe warning due to active OTP extraction!");
        assertTrue(result.getRiskScore() >= 50);
        assertTrue(result.getCategoriesTa().contains("OTP மோசடி"));
    }

    @Test
    @DisplayName("Tamil Fake Job Scam: பகுதி நேர வேலை. தினமும் 5000 சம்பாதிக்கலாம். வேலை உறுதி செய்ய கட்டணம் செலுத்தவும்.")
    void testTamilFakeJobScam() {
        String msg = "அரிய வாய்ப்பு! வீட்டில் இருந்தே பகுதி நேர வேலை. யூடியூப் லைக் பணி மூலம் தினசரி வருமானம் 5000. வேலை உறுதி செய்ய கட்டணம் செலுத்தவும்.";
        AnalysisResult result = detectionService.analyze(msg, "WhatsApp");

        System.out.println("Tamil Job Scam Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.getRiskScore() >= 50);
        assertTrue(result.getCategoriesTa().contains("போலியான வேலை வாய்ப்பு"));
    }

    @Test
    @DisplayName("Tamil Lottery Scam: நீங்கள் 25 லட்சம் ரொக்கப் பரிசு வென்றுள்ளீர்கள். பரிசு பெற கட்டணம் செலுத்தவும்.")
    void testTamilLotteryScam() {
        String msg = "வாழ்த்துகள்! குலுக்கலில் நீங்கள் 25 லட்சம் ரொக்கப் பரிசு வென்றுள்ளீர்கள். பரிசு பெற செயலாக்க கட்டணம் செலுத்தவும்.";
        AnalysisResult result = detectionService.analyze(msg, "WhatsApp");

        System.out.println("Tamil Lottery Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.getRiskScore() >= 40);
        assertTrue(result.getCategoriesTa().contains("பரிசு மற்றும் லாட்டரி மோசடி"));
    }

    @Test
    @DisplayName("Tamil KYC Phishing: உங்கள் KYC விவரங்களைப் புதுப்பிக்கவும். இல்லையெனில் கணக்கு முடக்கப்படும்.")
    void testTamilKycPhishing() {
        String msg = "அவசர அறிவிப்பு: உங்கள் KYC விவரங்களைப் புதுப்பிக்கவும். இல்லையெனில் உங்கள் கணக்கு முடக்கப்படும்.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil KYC Phishing Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.getRiskScore() >= 50);
        assertTrue(result.getCategoriesTa().contains("KYC புதுப்பிப்பு மோசடி"));
    }

    @Test
    @DisplayName("Tamil Electricity Bill Scam: மின்சாரக் கட்டணம் செலுத்தவில்லை. இன்றிரவு 9 மணிக்குள் மின் இணைப்பு துண்டிக்கப்படும்.")
    void testTamilElectricityScam() {
        String msg = "மின் வாரிய அறிவிப்பு: உங்கள் மின்சாரக் கட்டணம் செலுத்தவில்லை. இன்றிரவு 9 மணிக்குள் மின் இணைப்பு துண்டிக்கப்படும். உதவிக்கு அழைக்கவும்: 9876543210";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil Electricity Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.getRiskScore() >= 45);
        assertTrue(result.getCategoriesTa().contains("மின்சாரக் கட்டண மோசடி"));
    }

    @Test
    @DisplayName("Tamil Scam with Suspicious URL: இணைப்பைத் திறக்கவும் http://secure-bank-login.xyz")
    void testTamilScamWithUrl() {
        String msg = "உங்கள் வங்கி கணக்கு சரிபார்க்க கீழே உள்ள இணைப்பைத் திறக்கவும்: http://secure-bank-login.xyz உடனடியாக சரிபார்க்கவும்.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil with URL Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.getRiskScore() >= 50);
        assertFalse(result.getUrlFindings().isEmpty());
    }

    @Test
    @DisplayName("Tamil Threat & Payment: பணம் செலுத்தாவிட்டால் உங்கள் சேவை நிறுத்தப்படும் மற்றும் சட்ட நடவடிக்கை எடுக்கப்படும்.")
    void testTamilThreatAndPayment() {
        String msg = "கடைசி எச்சரிக்கை: பணம் செலுத்தாவிட்டால் உங்கள் சேவை நிறுத்தப்படும் மற்றும் சட்ட நடவடிக்கை எடுக்கப்படும்.";
        AnalysisResult result = detectionService.analyze(msg, "SMS");

        System.out.println("Tamil Threat Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertTrue(result.getRiskScore() >= 40);
        assertTrue(result.getCategoriesTa().contains("மிரட்டல் மற்றும் அவசரச் செய்திகள்") || result.getCategoriesTa().contains("பணப்பரிமாற்ற மோசடி"));
    }

    @Test
    @DisplayName("Benign Tamil Message: நாளை மாலை 5 மணிக்கு நூலகத்தில் சந்திப்போம்.")
    void testBenignTamilMessage() {
        String msg = "வணக்கம் செல்வா, நாளை மாலை 5 மணிக்கு நூலகத்தில் சந்திப்போம். புத்தகத்தை கொண்டு வரவும்.";
        AnalysisResult result = detectionService.analyze(msg, "WhatsApp");

        System.out.println("Benign Tamil Score: " + result.getRiskScore() + ", Categories: " + result.getCategoriesTa());
        assertEquals(0, result.getRiskScore());
        assertEquals(RiskScoringService.LEVEL_LOW, result.getRiskLevel());
        assertTrue(result.getCategories().isEmpty());
    }
}
