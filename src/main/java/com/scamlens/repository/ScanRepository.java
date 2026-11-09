package com.scamlens.repository;

import com.scamlens.model.Scan;
import com.scamlens.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {

    List<Scan> findByUserOrderByCreatedAtDesc(User user);

    List<Scan> findTop5ByUserOrderByCreatedAtDesc(User user);

    Optional<Scan> findByIdAndUser(Long id, User user);

    long countByUser(User user);

    long countByUserAndRiskLevel(User user, String riskLevel);

    @Query("SELECT AVG(s.riskScore) FROM Scan s WHERE s.user = :user")
    Double getAverageRiskScore(@Param("user") User user);

    @Query("SELECT s FROM Scan s WHERE s.user = :user AND " +
           "(:riskLevel IS NULL OR :riskLevel = '' OR LOWER(s.riskLevel) = LOWER(:riskLevel)) AND " +
           "(:category IS NULL OR :category = '' OR LOWER(s.scamCategory) LIKE LOWER(CONCAT('%', :category, '%'))) AND " +
           "(:keyword IS NULL OR :keyword = '' OR LOWER(s.originalMessage) LIKE LOWER(CONCAT('%', :keyword, '%'))) " +
           "ORDER BY s.createdAt DESC")
    List<Scan> searchScans(@Param("user") User user,
                           @Param("riskLevel") String riskLevel,
                           @Param("category") String category,
                           @Param("keyword") String keyword);
}
