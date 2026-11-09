package com.scamlens.service;

import com.scamlens.analyzer.*;
import com.scamlens.model.AnalysisResult;
import com.scamlens.model.ContextEvaluation;
import com.scamlens.model.ScamIndicator;
import com.scamlens.model.ScoreBreakdown;
import com.scamlens.model.UrlFinding;
import com.scamlens.util.InputSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class ScamDetectionService {

    private final MessageAnalyzer messageAnalyzer;
    private final ContextAnalyzer contextAnalyzer;
    private final ScamCategoryAnalyzer categoryAnalyzer;
    private final UrlAnalysisService urlAnalysisService;
    private final RiskScoringService riskScoringService;
    private final RecommendationService recommendationService;

    // Tamil Language Analysis Services
    private final TamilLanguageDetectionService tamilLanguageDetectionService;
    private final TamilTextNormalizer tamilTextNormalizer;
    private final TamilScamDictionary tamilDictionary;
    private final TamilNegationDetector tamilNegationDetector;
    private final TamilCredentialDetector tamilCredentialDetector;
    private final TamilActionDirectiveDetector tamilDirectiveDetector;
    private final TamilScamAnalyzer tamilScamAnalyzer;
    private final TamilRiskScoringService tamilRiskScoringService;

    @Autowired
    public ScamDetectionService(MessageAnalyzer messageAnalyzer,
                                ContextAnalyzer contextAnalyzer,
                                ScamCategoryAnalyzer categoryAnalyzer,
                                UrlAnalysisService urlAnalysisService,
                                RiskScoringService riskScoringService,
                                RecommendationService recommendationService,
                                TamilLanguageDetectionService tamilLanguageDetectionService,
                                TamilTextNormalizer tamilTextNormalizer,
                                TamilScamDictionary tamilDictionary,
                                TamilNegationDetector tamilNegationDetector,
                                TamilCredentialDetector tamilCredentialDetector,
                                TamilActionDirectiveDetector tamilDirectiveDetector,
                                TamilScamAnalyzer tamilScamAnalyzer,
                                TamilRiskScoringService tamilRiskScoringService) {
        this.messageAnalyzer = messageAnalyzer;
        this.contextAnalyzer = contextAnalyzer;
        this.categoryAnalyzer = categoryAnalyzer;
        this.urlAnalysisService = urlAnalysisService;
        this.riskScoringService = riskScoringService;
        this.recommendationService = recommendationService;
        this.tamilLanguageDetectionService = tamilLanguageDetectionService;
        this.tamilTextNormalizer = tamilTextNormalizer;
        this.tamilDictionary = tamilDictionary;
        this.tamilNegationDetector = tamilNegationDetector;
        this.tamilCredentialDetector = tamilCredentialDetector;
        this.tamilDirectiveDetector = tamilDirectiveDetector;
        this.tamilScamAnalyzer = tamilScamAnalyzer;
        this.tamilRiskScoringService = tamilRiskScoringService;
    }

    /**
     * Backward-compatible constructor for standalone testing.
     */
    public ScamDetectionService(MessageAnalyzer messageAnalyzer,
                                ContextAnalyzer contextAnalyzer,
                                ScamCategoryAnalyzer categoryAnalyzer,
                                UrlAnalysisService urlAnalysisService,
                                RiskScoringService riskScoringService,
                                RecommendationService recommendationService) {
        this(messageAnalyzer, contextAnalyzer, categoryAnalyzer, urlAnalysisService, riskScoringService, recommendationService,
                new TamilLanguageDetectionService(),
                new TamilTextNormalizer(),
                new TamilScamDictionary(),
                new TamilNegationDetector(),
                new TamilCredentialDetector(),
                new TamilActionDirectiveDetector(),
                new TamilScamAnalyzer(new TamilScamDictionary(), new TamilTextNormalizer(), new TamilNegationDetector(), new TamilCredentialDetector(), new TamilActionDirectiveDetector()),
                new TamilRiskScoringService(new TamilScamDictionary()));
    }

    /**
     * Executes the comprehensive Java scam detection engine supporting English and authentic Tamil script.
     */
    public AnalysisResult analyze(String rawMessage, String sourceType) {
        String message = InputSanitizer.sanitize(rawMessage);

        AnalysisResult result = new AnalysisResult();
        result.setOriginalMessage(message);
        result.setSourceType((sourceType != null && !sourceType.trim().isEmpty()) ? sourceType : "Auto Detect");

        if (message.isEmpty()) {
            result.setRiskScore(0);
            result.setRiskLevel(RiskScoringService.LEVEL_LOW);
            result.setDetectedLanguage(TamilLanguageDetectionService.LANG_ENGLISH);
            result.setLanguageCode(TamilLanguageDetectionService.CODE_ENGLISH);
            result.setContextEvaluation(contextAnalyzer.evaluateContext(""));
            result.setScoreBreakdown(riskScoringService.generateScoreBreakdown(Collections.emptyList(), result.getContextEvaluation(), false));
            result.getRecommendations().add("Empty message provided. Please enter text or a URL to analyze.");
            result.getRecommendationsTa().add("செய்தி எதுவும் உள்ளிடப்படவில்லை. தயவுசெய்து பகுப்பாய்வு செய்ய உரையை உள்ளிடவும்.");
            return result;
        }

        // 1. Language Detection (English vs Tamil vs Multilingual)
        boolean hasTamil = tamilLanguageDetectionService.containsTamil(message);
        String detectedLang = tamilLanguageDetectionService.detectLanguage(message);
        String langCode = tamilLanguageDetectionService.getLanguageCode(message);

        result.setDetectedLanguage(detectedLang);
        result.setLanguageCode(langCode);

        // 2. Branch: Tamil vs English Engine
        if (hasTamil) {
            analyzeTamilContent(message, result);
        } else {
            analyzeEnglishContent(message, result);
        }

        // 3. Populate bilingual recommendations
        result.setRecommendations(recommendationService.generateRecommendations(result));
        result.setRecommendationsTa(recommendationService.generateRecommendationsTa(result));

        return result;
    }

    /**
     * Comprehensive Tamil Semantic Analysis Pipeline.
     */
    private void analyzeTamilContent(String message, AnalysisResult result) {
        String normalized = tamilTextNormalizer.normalize(message);
        List<String> sentences = tamilTextNormalizer.splitSentences(normalized);

        // A. Credentials & Action Directives Detection
        List<TamilCredentialDetector.CredentialMatch> credentials = new ArrayList<>();
        List<TamilActionDirectiveDetector.ActionDirective> directives = new ArrayList<>();

        for (String s : sentences) {
            credentials.addAll(tamilCredentialDetector.detectCredentials(s));
            directives.addAll(tamilDirectiveDetector.detectDirectives(s));
        }

        List<String> credTargets = new ArrayList<>();
        for (TamilCredentialDetector.CredentialMatch c : credentials) {
            credTargets.add(c.getEnglishName() + " (" + c.getTerm() + ")");
        }
        result.setCredentialTargets(credTargets);

        List<String> actionStrings = new ArrayList<>();
        for (TamilActionDirectiveDetector.ActionDirective d : directives) {
            actionStrings.add(d.toString());
        }
        result.setActionDirectives(actionStrings);

        // B. Context-Aware Negation Evaluation
        TamilNegationDetector.TamilNegationEvaluation negationEval = tamilNegationDetector.evaluate(normalized, credentials, directives);
        boolean isWarning = negationEval.isProtectiveSafetyWarning();
        result.setWarningContext(isWarning);

        ContextEvaluation contextEval = new ContextEvaluation();
        contextEval.setNegationDetected(negationEval.isContainsNegation());
        contextEval.setNegationPhrases(negationEval.getDetectedNegationTokens());
        contextEval.setWarningAdvisory(isWarning);
        contextEval.setActionDirectives(actionStrings);
        contextEval.setCredentialTargets(credTargets);

        if (isWarning) {
            contextEval.setIntentType("LEGITIMATE_WARNING");
            contextEval.setIntentTypeTa("சட்டபூர்வ பாதுகாப்பு எச்சரிக்கை");
            contextEval.setIntentDescription("Institutional Safety Warning: Protects user credentials and cautions against disclosure.");
            contextEval.setIntentDescriptionTa("நிறுவன பாதுகாப்பு விழிப்புணர்வு: ரகசிய விவரங்களைப் பகிர வேண்டாம் என பயனர்களை எச்சரிக்கிறது.");
        } else if (!credentials.isEmpty() && credentials.stream().anyMatch(c -> c.getIntent() == TamilCredentialDetector.CredentialIntent.REQUESTED)) {
            contextEval.setIntentType("ACTIVE_SCAM_REQUEST");
            contextEval.setIntentTypeTa("தீங்கிழைக்கும் மோசடி முயற்சி");
            contextEval.setIntentDescription("Active Scam Directive: Directly commands recipient to disclose sensitive credentials.");
            contextEval.setIntentDescriptionTa("நேரடி மோசடி கட்டளை: ரகசிய குறியீடுகள் அல்லது OTP-ஐ வழங்குமாறு நேரடியாக கோருகிறது.");
            contextEval.setRequestIntentDetected(true);
        } else if (!directives.isEmpty() || normalized.contains("முடக்கப்படும்") || normalized.contains("துண்டிக்கப்படும்")) {
            contextEval.setIntentType("SUSPICIOUS_DEMAND");
            contextEval.setIntentTypeTa("சந்தேகத்திற்கிடமான அவசர கோரிக்கை");
            contextEval.setIntentDescription("Coercive Threat / Immediate Demand: Imposes artificial urgency, suspension, or fee demands.");
            contextEval.setIntentDescriptionTa("அச்சுறுத்தல் மற்றும் அவசர கோரிக்கை: கணக்கு முடக்கம் அல்லது கட்டணம் செலுத்த வற்புறுத்துகிறது.");
        } else {
            contextEval.setIntentType("BENIGN_COMMUNICATION");
            contextEval.setIntentTypeTa("இயல்பான தகவல் தொடர்பு");
            contextEval.setIntentDescription("Benign Tamil Communication: No threat, credential harvesting, or payment demand patterns.");
            contextEval.setIntentDescriptionTa("இயல்பான உரையாடல்: அச்சுறுத்தல் அல்லது மோசடி கோரிக்கைகள் எதுவும் இல்லை.");
        }

        result.setContextEvaluation(contextEval);

        // C. Structural Urgency Check
        boolean hasExcessiveUrgency = message.contains("!!!") || message.contains("???") ||
                message.contains("உடனடியாக") && message.contains("24 மணி");

        // D. Category Indicators Detection
        List<ScamIndicator> indicators = new ArrayList<>();
        if (!isWarning) {
            indicators.addAll(tamilScamAnalyzer.analyze(normalized));
        }

        // E. URL Analysis (Combined Message + Passive URL Inspection)
        List<UrlFinding> urlFindings = urlAnalysisService.analyzeUrlsInText(message);
        result.setUrlFindings(urlFindings);

        if (!isWarning && !urlFindings.isEmpty()) {
            List<ScamIndicator> urlIndicators = urlAnalysisService.extractUrlIndicators(urlFindings);
            // Translate URL indicators to bilingual
            for (ScamIndicator uInd : urlIndicators) {
                uInd.setCategoryTa(TamilScamDictionary.CAT_PHISHING_URL);
                uInd.setNameTa("சந்தேகத்திற்கிடமான இணைய இணைப்பு");
                uInd.setExplanationTa("செய்தியில் உள்ள இணையதள இணைப்பு ஏமாற்று பண்புகளைக் கொண்டுள்ளது.");
            }
            indicators.addAll(urlIndicators);
        }

        result.setIndicators(indicators);

        // F. Distinct Categories, Phrases, Explanations (Bilingual)
        Set<String> categoriesEn = new LinkedHashSet<>();
        Set<String> categoriesTa = new LinkedHashSet<>();
        Set<String> phrases = new LinkedHashSet<>();
        Set<String> explanationsEn = new LinkedHashSet<>();
        Set<String> explanationsTa = new LinkedHashSet<>();

        for (ScamIndicator ind : indicators) {
            categoriesEn.add(ind.getCategory());
            if (ind.getCategoryTa() != null) {
                categoriesTa.add(ind.getCategoryTa());
            }
            if (ind.getMatchedPhrase() != null && !ind.getMatchedPhrase().trim().isEmpty()) {
                phrases.add(ind.getMatchedPhrase());
            }
            if (ind.getExplanation() != null) {
                explanationsEn.add(ind.getExplanation());
            }
            if (ind.getExplanationTa() != null) {
                explanationsTa.add(ind.getExplanationTa());
            }
        }

        if (isWarning) {
            categoriesEn.add("Legitimate Security Advisory");
            categoriesTa.add(TamilScamDictionary.CAT_SECURITY_ADVISORY);
            explanationsEn.add("Message recognized as an official Tamil security warning advising against disclosing credentials.");
            explanationsTa.add("இச்செய்தி அங்கீகரிக்கப்பட்ட விழிப்புணர்வு அல்லது பாதுகாப்பு எச்சரிக்கை அறிவிப்பாகும்.");
        }

        result.setCategories(new ArrayList<>(categoriesEn));
        result.setCategoriesTa(new ArrayList<>(categoriesTa));
        result.setSuspiciousPhrases(new ArrayList<>(phrases));
        result.setExplanations(new ArrayList<>(explanationsEn));
        result.setExplanationsTa(new ArrayList<>(explanationsTa));

        // G. Risk Scoring Breakdown
        ScoreBreakdown scoreBreakdown = tamilRiskScoringService.calculateBreakdown(indicators, contextEval, hasExcessiveUrgency);
        result.setScoreBreakdown(scoreBreakdown);
        result.setRiskScore(scoreBreakdown.getFinalScore());
        result.setRiskLevel(scoreBreakdown.getRiskLevel());
    }

    /**
     * Existing English Analysis Pipeline.
     */
    private void analyzeEnglishContent(String message, AnalysisResult result) {
        // 1. Context-Aware Intent Evaluation
        ContextEvaluation contextEval = contextAnalyzer.evaluateContext(message);
        result.setContextEvaluation(contextEval);
        boolean isWarning = contextEval.isWarningAdvisory();
        result.setWarningContext(isWarning);

        // Populate directives and credential targets for consistency
        result.setCredentialTargets(contextEval.getRequestedCredentials());
        result.setActionDirectives(contextEval.getSuspiciousActionsIdentified());

        // 2. Structural & Urgency Check
        boolean hasExcessiveUrgency = messageAnalyzer.hasExcessiveUppercase(message) ||
                messageAnalyzer.hasExcessivePunctuation(message);

        // 3. Category Indicators Detection
        List<ScamIndicator> indicators = new ArrayList<>(categoryAnalyzer.detectIndicators(message));

        // 4. URL Analysis
        List<UrlFinding> urlFindings = urlAnalysisService.analyzeUrlsInText(message);
        result.setUrlFindings(urlFindings);

        if (!isWarning) {
            List<ScamIndicator> urlIndicators = urlAnalysisService.extractUrlIndicators(urlFindings);
            indicators.addAll(urlIndicators);
        }

        result.setIndicators(indicators);

        // 5. Distinct Categories & Suspicious Phrases
        Set<String> categories = new LinkedHashSet<>();
        Set<String> categoriesTa = new LinkedHashSet<>();
        Set<String> phrases = new LinkedHashSet<>();
        Set<String> explanations = new LinkedHashSet<>();
        Set<String> explanationsTa = new LinkedHashSet<>();

        for (ScamIndicator ind : indicators) {
            categories.add(ind.getCategory());
            String catTa = tamilDictionary.getTamilCategory(ind.getCategory());
            categoriesTa.add(catTa);

            if (ind.getMatchedPhrase() != null && !ind.getMatchedPhrase().trim().isEmpty()) {
                phrases.add(ind.getMatchedPhrase());
            }
            if (ind.getExplanation() != null) {
                explanations.add(ind.getExplanation());
                explanationsTa.add(ind.getExplanationTa() != null ? ind.getExplanationTa() : ind.getExplanation());
            }
        }

        if (isWarning) {
            categories.add("Legitimate Security Advisory");
            categoriesTa.add(TamilScamDictionary.CAT_SECURITY_ADVISORY);
            explanations.add("Message recognized as an awareness warning or educational alert advising against disclosing credentials.");
            explanationsTa.add("இச்செய்தி அங்கீகரிக்கப்பட்ட விழிப்புணர்வு அல்லது பாதுகாப்பு எச்சரிக்கை அறிவிப்பாகும்.");
        }

        result.setCategories(new ArrayList<>(categories));
        result.setCategoriesTa(new ArrayList<>(categoriesTa));
        result.setSuspiciousPhrases(new ArrayList<>(phrases));
        result.setExplanations(new ArrayList<>(explanations));
        result.setExplanationsTa(new ArrayList<>(explanationsTa));

        // 6. Explainable Multi-Indicator Risk Scoring & Breakdown
        ScoreBreakdown scoreBreakdown = riskScoringService.generateScoreBreakdown(indicators, contextEval, hasExcessiveUrgency);
        result.setScoreBreakdown(scoreBreakdown);
        result.setRiskScore(scoreBreakdown.getFinalScore());
        result.setRiskLevel(scoreBreakdown.getRiskLevel());
    }
}
