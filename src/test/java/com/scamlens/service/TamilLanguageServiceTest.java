package com.scamlens.service;

import com.scamlens.analyzer.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TamilLanguageServiceTest {

    private TamilLanguageDetectionService langService;
    private TamilTextNormalizer normalizer;
    private TamilNegationDetector negationDetector;
    private TamilCredentialDetector credentialDetector;
    private TamilActionDirectiveDetector directiveDetector;

    @BeforeEach
    void setUp() {
        langService = new TamilLanguageDetectionService();
        normalizer = new TamilTextNormalizer();
        negationDetector = new TamilNegationDetector();
        credentialDetector = new TamilCredentialDetector();
        directiveDetector = new TamilActionDirectiveDetector();
    }

    @Test
    @DisplayName("Should detect Tamil script accurately")
    void testDetectTamil() {
        assertTrue(langService.containsTamil("உங்கள் வங்கி கணக்கு முடக்கப்படும்."));
        assertEquals("Tamil", langService.detectLanguage("உங்கள் வங்கி கணக்கு முடக்கப்படும்."));
        assertEquals("ta", langService.getLanguageCode("உங்கள் வங்கி கணக்கு முடக்கப்படும்."));
    }

    @Test
    @DisplayName("Should detect English accurately and not trigger on pure English")
    void testDetectEnglish() {
        assertFalse(langService.containsTamil("Your bank account will be suspended within 24 hours."));
        assertEquals("English", langService.detectLanguage("Your bank account will be suspended within 24 hours."));
        assertEquals("en", langService.getLanguageCode("Your bank account will be suspended within 24 hours."));
    }

    @Test
    @DisplayName("Should detect Multilingual when Tamil text has English technical terms (OTP, PIN, URL)")
    void testMixedTechnicalTerms() {
        String mixed = "உங்கள் OTP மற்றும் PIN எண்ணை யாரிடமும் பகிர வேண்டாம். http://sbi.co.in/security";
        assertTrue(langService.containsTamil(mixed));
        assertEquals("ta", langService.getLanguageCode(mixed));
    }

    @Test
    @DisplayName("Should normalize Unicode and remove invisible zero-width characters")
    void testUnicodeNormalization() {
        String dirty = "வங்\u200Cகி கணக்\u200Dகு \uFEFFமுடக்கப்\u200Eபடும்.";
        String clean = normalizer.normalize(dirty);

        assertFalse(clean.contains("\u200C"));
        assertFalse(clean.contains("\u200D"));
        assertFalse(clean.contains("\uFEFF"));
        assertEquals("வங்கி கணக்கு முடக்கப்படும்.", clean);
    }

    @Test
    @DisplayName("Should detect credentials and distinguish request vs warning vs mention")
    void testCredentialDetector() {
        // Requested
        List<TamilCredentialDetector.CredentialMatch> matches1 = credentialDetector.detectCredentials("உடனடியாக உங்கள் OTP எண்ணை அனுப்பவும்.");
        assertFalse(matches1.isEmpty());
        assertEquals(TamilCredentialDetector.CredentialIntent.REQUESTED, matches1.get(0).getIntent());

        // Warned against
        List<TamilCredentialDetector.CredentialMatch> matches2 = credentialDetector.detectCredentials("உங்கள் கடவுச்சொல்லை யாரிடமும் பகிர வேண்டாம்.");
        assertFalse(matches2.isEmpty());
        assertEquals(TamilCredentialDetector.CredentialIntent.WARNED_AGAINST, matches2.get(0).getIntent());
    }

    @Test
    @DisplayName("Should detect action directives and their targets")
    void testActionDirectiveDetector() {
        String text = "கீழே உள்ள இணைப்பைத் திறக்கவும் மற்றும் உடனடியாக பதிவு செய்யவும்.";
        List<TamilActionDirectiveDetector.ActionDirective> directives = directiveDetector.detectDirectives(text);

        assertTrue(directives.stream().anyMatch(d -> "Open".equals(d.getEnglishAction())));
        assertTrue(directives.stream().anyMatch(d -> "Register".equals(d.getEnglishAction())));
    }
}
