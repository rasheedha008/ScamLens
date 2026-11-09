package com.scamlens.repository;

import com.scamlens.model.Scan;
import com.scamlens.model.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@TestPropertySource(locations = "classpath:application-test.properties")
class ScanRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private ScanRepository scanRepository;

    @Test
    @DisplayName("Should persist and retrieve user-specific scans correctly")
    void testUserSpecificScans() {
        User user1 = new User("User One", "user1@example.com", "hash1");
        User user2 = new User("User Two", "user2@example.com", "hash2");
        entityManager.persist(user1);
        entityManager.persist(user2);

        Scan scan1 = new Scan();
        scan1.setUser(user1);
        scan1.setOriginalMessage("Scan for user 1");
        scan1.setSourceType("SMS");
        scan1.setRiskScore(70);
        scan1.setRiskLevel("High");
        scan1.setScamCategory("Phishing");
        entityManager.persist(scan1);

        Scan scan2 = new Scan();
        scan2.setUser(user2);
        scan2.setOriginalMessage("Scan for user 2");
        scan2.setSourceType("Email");
        scan2.setRiskScore(10);
        scan2.setRiskLevel("Low");
        scan2.setScamCategory("None");
        entityManager.persist(scan2);

        entityManager.flush();

        // Query user 1 scans
        List<Scan> user1Scans = scanRepository.findByUserOrderByCreatedAtDesc(user1);
        assertEquals(1, user1Scans.size());
        assertEquals("Scan for user 1", user1Scans.get(0).getOriginalMessage());

        // Count operations
        assertEquals(1, scanRepository.countByUser(user1));
        assertEquals(1, scanRepository.countByUserAndRiskLevel(user1, "High"));
        assertEquals(0, scanRepository.countByUserAndRiskLevel(user1, "Low"));

        // User 2 records must remain isolated
        List<Scan> user2Scans = scanRepository.findByUserOrderByCreatedAtDesc(user2);
        assertEquals(1, user2Scans.size());
        assertEquals("Scan for user 2", user2Scans.get(0).getOriginalMessage());
    }

    @Test
    @DisplayName("Should compute average risk score in database")
    void testAverageRiskScore() {
        User user = new User("User Calc", "calc@example.com", "hash");
        entityManager.persist(user);

        Scan s1 = new Scan();
        s1.setUser(user);
        s1.setOriginalMessage("Message 1");
        s1.setSourceType("SMS");
        s1.setRiskScore(60);
        s1.setRiskLevel("High");
        entityManager.persist(s1);

        Scan s2 = new Scan();
        s2.setUser(user);
        s2.setOriginalMessage("Message 2");
        s2.setSourceType("SMS");
        s2.setRiskScore(80);
        s2.setRiskLevel("Critical");
        entityManager.persist(s2);

        entityManager.flush();

        Double avg = scanRepository.getAverageRiskScore(user);
        assertNotNull(avg);
        assertEquals(70.0, avg);
    }
}
