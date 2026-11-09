-- =====================================================================
-- ScamLens Database Initialization Script (MySQL 8.x)
-- Intelligent Scam Detection and Cybersecurity Analysis Platform
-- =====================================================================

CREATE DATABASE IF NOT EXISTS scamlens
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE scamlens;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Scans Table
CREATE TABLE IF NOT EXISTS scans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    original_message LONGTEXT NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    risk_score INT NOT NULL,
    risk_level VARCHAR(30) NOT NULL,
    scam_category VARCHAR(255),
    detected_indicators LONGTEXT,
    explanations LONGTEXT,
    url_findings LONGTEXT,
    recommendations LONGTEXT,
    context_evaluation LONGTEXT,
    score_breakdown LONGTEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_scan_user (user_id),
    INDEX idx_scan_risk_level (risk_level),
    INDEX idx_scan_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Optional initial seed user (password: password123)
-- BCrypt hash for 'password123': $2a$10$76g.p5nS7uS8.5/VzBqOvuM2FvN92X5T1G.L4P/8J3QZ5X0W9K02S
INSERT INTO users (name, email, password, created_at, updated_at)
VALUES ('Security Analyst', 'demo@scamlens.com', '$2a$10$76g.p5nS7uS8.5/VzBqOvuM2FvN92X5T1G.L4P/8J3QZ5X0W9K02S', NOW(), NOW())
ON DUPLICATE KEY UPDATE name=name;
