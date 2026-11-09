package com.scamlens.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.scamlens.dto.ScanResponse;
import com.scamlens.exception.ResourceNotFoundException;
import com.scamlens.exception.UnauthorizedAccessException;
import com.scamlens.model.*;
import com.scamlens.repository.ScanRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ScanService {

    private final ScanRepository scanRepository;
    private final ObjectMapper objectMapper;
    private final RecommendationService recommendationService;

    @Autowired
    public ScanService(ScanRepository scanRepository, ObjectMapper objectMapper, RecommendationService recommendationService) {
        this.scanRepository = scanRepository;
        this.objectMapper = objectMapper;
        this.recommendationService = recommendationService;
    }

    public ScanService(ScanRepository scanRepository, ObjectMapper objectMapper) {
        this(scanRepository, objectMapper, new RecommendationService());
    }

    /**
     * Persists an analysis result linked to the authenticated user.
     */
    @Transactional
    public Scan saveScan(AnalysisResult result, User user) {
        Scan scan = new Scan();
        scan.setUser(user);
        scan.setOriginalMessage(result.getOriginalMessage());
        scan.setSourceType(result.getSourceType());
        scan.setRiskScore(result.getRiskScore());
        scan.setRiskLevel(result.getRiskLevel());

        List<String> enCats = result.getCategories() != null ? result.getCategories() : List.of();
        List<String> taCats = result.getCategoriesTa() != null ? result.getCategoriesTa() : List.of();
        String catString;
        if (!taCats.isEmpty() && !enCats.isEmpty()) {
            catString = String.join(", ", enCats) + " | " + String.join(", ", taCats);
        } else if (!enCats.isEmpty()) {
            catString = String.join(", ", enCats);
        } else if (!taCats.isEmpty()) {
            catString = String.join(", ", taCats);
        } else {
            catString = "None";
        }
        scan.setScamCategory(catString);
        scan.setDetectedLanguage(result.getDetectedLanguage());

        try {
            scan.setDetectedIndicators(objectMapper.writeValueAsString(result.getIndicators()));
            scan.setExplanations(objectMapper.writeValueAsString(result.getExplanations()));
            scan.setUrlFindings(objectMapper.writeValueAsString(result.getUrlFindings()));
            scan.setRecommendations(objectMapper.writeValueAsString(result.getRecommendations()));
            if (result.getContextEvaluation() != null) {
                scan.setContextEvaluation(objectMapper.writeValueAsString(result.getContextEvaluation()));
            }
            if (result.getScoreBreakdown() != null) {
                scan.setScoreBreakdown(objectMapper.writeValueAsString(result.getScoreBreakdown()));
            }
        } catch (Exception e) {
            scan.setDetectedIndicators("[]");
            scan.setExplanations("[]");
            scan.setUrlFindings("[]");
            scan.setRecommendations("[]");
        }

        return scanRepository.save(scan);
    }

    /**
     * Retrieves all scans for the user, ordered by date descending.
     */
    public List<ScanResponse> getUserScans(User user) {
        List<Scan> scans = scanRepository.findByUserOrderByCreatedAtDesc(user);
        return scans.stream().map(this::toResponse).collect(Collectors.toList());
    }

    /**
     * Searches and filters user scans.
     */
    public List<ScanResponse> searchUserScans(User user, String riskLevel, String category, String keyword) {
        List<Scan> scans = scanRepository.searchScans(user, riskLevel, category, keyword);
        return scans.stream().map(this::toResponse).collect(Collectors.toList());
    }

    /**
     * Retrieves a single scan by ID verifying user ownership.
     */
    public Scan getScanByIdAndUser(Long id, User user) {
        Scan scan = scanRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Scan record not found with ID: " + id));

        if (!scan.getUser().getId().equals(user.getId())) {
            throw new UnauthorizedAccessException("You are not authorized to view this scan record.");
        }

        return scan;
    }

    /**
     * Returns ScanResponse DTO for a specific scan verifying user ownership.
     */
    public ScanResponse getScanResponseByIdAndUser(Long id, User user) {
        Scan scan = getScanByIdAndUser(id, user);
        return toResponse(scan);
    }

    /**
     * Deletes a scan record verifying user ownership.
     */
    @Transactional
    public void deleteScan(Long id, User user) {
        Scan scan = getScanByIdAndUser(id, user);
        scanRepository.delete(scan);
    }

    /**
     * Converts a transient AnalysisResult to ScanResponse.
     */
    public ScanResponse toResponse(AnalysisResult result) {
        ScanResponse response = new ScanResponse();
        response.setOriginalMessage(result.getOriginalMessage());
        response.setSourceType(result.getSourceType());
        response.setRiskScore(result.getRiskScore());
        response.setRiskLevel(result.getRiskLevel());
        response.setDetectedLanguage(result.getDetectedLanguage());
        response.setLanguageCode(result.getLanguageCode());
        response.setCategories(result.getCategories());
        response.setCategoriesTa(result.getCategoriesTa());
        response.setIndicators(result.getIndicators());
        response.setSuspiciousPhrases(result.getSuspiciousPhrases());
        response.setExplanations(result.getExplanations());
        response.setExplanationsTa(result.getExplanationsTa());
        response.setUrlFindings(result.getUrlFindings());
        response.setRecommendations(result.getRecommendations());
        response.setRecommendationsTa(result.getRecommendationsTa());
        response.setActionDirectives(result.getActionDirectives());
        response.setCredentialTargets(result.getCredentialTargets());
        response.setWarningContext(result.isWarningContext());
        response.setContextEvaluation(result.getContextEvaluation());
        response.setScoreBreakdown(result.getScoreBreakdown());
        response.setCreatedAt(result.getAnalyzedAt());
        return response;
    }

    /**
     * Converts Scan entity to ScanResponse.
     */
    public ScanResponse toResponse(Scan scan) {
        ScanResponse response = new ScanResponse();
        response.setId(scan.getId());
        response.setOriginalMessage(scan.getOriginalMessage());
        response.setSourceType(scan.getSourceType());
        response.setRiskScore(scan.getRiskScore());
        response.setRiskLevel(scan.getRiskLevel());
        response.setDetectedLanguage(scan.getDetectedLanguage() != null ? scan.getDetectedLanguage() : "English");
        boolean isTamil = scan.getDetectedLanguage() != null && scan.getDetectedLanguage().contains("Tamil");
        response.setLanguageCode(isTamil ? "ta" : "en");
        response.setCreatedAt(scan.getCreatedAt());

        if (scan.getScamCategory() != null && !scan.getScamCategory().trim().isEmpty()) {
            String raw = scan.getScamCategory().trim();
            if (raw.contains("|")) {
                String[] parts = raw.split("\\|", 2);
                String enPart = parts[0].trim();
                String taPart = parts[1].trim();
                if (!enPart.isEmpty() && !enPart.equalsIgnoreCase("None")) {
                    response.setCategories(List.of(enPart.split(",\\s*")));
                }
                if (!taPart.isEmpty() && !taPart.equalsIgnoreCase("None")) {
                    response.setCategoriesTa(List.of(taPart.split(",\\s*")));
                }
            } else {
                response.setCategories(List.of(raw.split(",\\s*")));
            }
        }

        try {
            if (scan.getDetectedIndicators() != null) {
                List<ScamIndicator> indicators = objectMapper.readValue(
                        scan.getDetectedIndicators(),
                        new TypeReference<List<ScamIndicator>>() {}
                );
                response.setIndicators(indicators);
                List<String> phrases = new ArrayList<>();
                for (ScamIndicator ind : indicators) {
                    if (ind.getMatchedPhrase() != null && !ind.getMatchedPhrase().trim().isEmpty()) {
                        phrases.add(ind.getMatchedPhrase());
                    }
                }
                response.setSuspiciousPhrases(phrases);
            }
            if (scan.getExplanations() != null) {
                response.setExplanations(objectMapper.readValue(
                        scan.getExplanations(),
                        new TypeReference<List<String>>() {}
                ));
            }
            if (scan.getUrlFindings() != null) {
                response.setUrlFindings(objectMapper.readValue(
                        scan.getUrlFindings(),
                        new TypeReference<List<UrlFinding>>() {}
                ));
            }
            if (scan.getRecommendations() != null) {
                response.setRecommendations(objectMapper.readValue(
                        scan.getRecommendations(),
                        new TypeReference<List<String>>() {}
                ));
            }
            if (scan.getContextEvaluation() != null) {
                response.setContextEvaluation(objectMapper.readValue(
                        scan.getContextEvaluation(),
                        ContextEvaluation.class
                ));
                if (response.getContextEvaluation() != null) {
                    response.setWarningContext(response.getContextEvaluation().isWarningAdvisory());
                }
            }
            if (scan.getScoreBreakdown() != null) {
                response.setScoreBreakdown(objectMapper.readValue(
                        scan.getScoreBreakdown(),
                        ScoreBreakdown.class
                ));
            }

            if ((response.getCategoriesTa() == null || response.getCategoriesTa().isEmpty()) && response.getCategories() != null) {
                List<String> catsTa = new ArrayList<>();
                for (String cat : response.getCategories()) {
                    String ta = com.scamlens.analyzer.TamilScamDictionary.toTamilCategory(cat);
                    catsTa.add(ta != null ? ta : cat);
                }
                response.setCategoriesTa(catsTa);
            }

            if ((response.getCategories() == null || response.getCategories().isEmpty()) && response.getCategoriesTa() != null) {
                List<String> catsEn = new ArrayList<>();
                for (String cat : response.getCategoriesTa()) {
                    String en = com.scamlens.analyzer.TamilScamDictionary.toEnglishCategory(cat);
                    catsEn.add(en != null ? en : cat);
                }
                response.setCategories(catsEn);
            }

            if (response.getContextEvaluation() != null) {
                if (response.getContextEvaluation().getActionDirectives() != null) {
                    response.setActionDirectives(response.getContextEvaluation().getActionDirectives());
                }
                if (response.getContextEvaluation().getCredentialTargets() != null) {
                    response.setCredentialTargets(response.getContextEvaluation().getCredentialTargets());
                }
            }

            if (recommendationService != null && (isTamil || "ta".equalsIgnoreCase(response.getLanguageCode()))) {
                AnalysisResult dummyResult = new AnalysisResult();
                dummyResult.setRiskScore(response.getRiskScore());
                dummyResult.setCategories(response.getCategories() != null ? response.getCategories() : List.of());
                dummyResult.setCategoriesTa(response.getCategoriesTa() != null ? response.getCategoriesTa() : List.of());
                dummyResult.setUrlFindings(response.getUrlFindings() != null ? response.getUrlFindings() : List.of());
                dummyResult.setWarningContext(response.isWarningContext());
                response.setRecommendationsTa(recommendationService.generateRecommendationsTa(dummyResult));
            }
        } catch (Exception e) {
            // Fallback gracefully
        }

        return response;
    }
}
