# ScamLens – Intelligent Scam Detection and Cybersecurity Analysis Platform

**Tagline:** *Think Before You Click. Stay Ahead of Scams.*

[![Java Version](https://img.shields.io/badge/Java-17%20%7C%2021-blue.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Security](https://img.shields.io/badge/Spring%20Security-6-red.svg)](https://spring.io/projects/spring-security)
[![Database](https://img.shields.io/badge/Database-MySQL%208.x%20%7C%20H2-orange.svg)](https://www.mysql.com/)
[![Tests](https://img.shields.io/badge/Automated%20Tests-80%20Passed-success.svg)](#12-automated-test-suite)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

---

## 1. Executive Summary

**ScamLens** is an enterprise-grade cybersecurity analysis platform engineered to protect digital citizens from social engineering attacks, credential harvesting, financial deception, and malicious links. Built entirely on a **100% pure Java backend using Spring Boot 3**, ScamLens provides heuristic risk scoring, semantic context awareness, passive link inspection, dynamic analytics, side-by-side message comparison, and downloadable incident reports.

---

## 2. Three Major Innovations of ScamLens

ScamLens introduces three major architectural innovations that overcome the limitations of legacy keyword scanners:

### Innovation 1: Context-Aware Rule-Based Scam Detection
- **Semantic Intent Analysis:** Analyzes the meaning and intent of messages rather than relying only on suspicious keywords.
- **Warnings vs Attacks Differentiation:** Differentiates between legitimate security warnings (e.g., *"State Bank never asks for your OTP or password"*) and actual scam requests (*"Share your OTP immediately to verify account"*).
- **Advanced Context Engine:** Uses negation detection (20+ protective warning prefixes), request-intent recognition, and suspicious-action identification (external link clicking, remote desktop installation, unverified calling directives).

### Innovation 2: Explainable Multi-Indicator Risk Assessment
- **Weighted Heuristics:** Evaluates multiple suspicious indicators using a weighted risk-scoring mechanism with distinct category weights and safety caps.
- **Calibrated 0–100 Scale:** Generates a reliable, mathematically bounded risk score between 0 and 100 without arbitrary guessing.
- **Full Explainability:** Provides transparent explanations for detected threats, suspicious phrases, category caps, context adjustments, and assigned risk levels (Low, Medium, High, Critical).

### Innovation 3: Integrated User-Centric Cybersecurity Platform
- **Dual-Vector Analysis:** Combines message content analysis and passive zero-execution URL analysis in a single unified interface.
- **ScamLens Compare:** Allows side-by-side comparison of two suspicious messages to contrast risk scores, semantic intent, and category differences.
- **Personalized Audit Vault & Awareness:** Maintains user-specific scan history, dynamic Chart.js dashboards, downloadable OpenPDF incident reports, and a 10-module Scam Intelligence Center.

---

## 3. Core Problem Statement

Conventional anti-phishing solutions typically suffer from critical deficiencies:
1. **Isolated Analysis:** They analyze either isolated text keywords or URLs independently, missing compound social engineering attacks.
2. **Context Blindness:** Naive keyword-matching flags legitimate bank security warnings (e.g., *"Never share your OTP with anyone"*) as high-risk threats because sensitive terms appear.
3. **Double Counting & Random Scores:** Lack of category caps leads to inflated or arbitrary risk scores without verifiable heuristics.
4. **Active Scanning Risks:** Many link checkers execute requests to target servers, risking malware downloads or triggering server-side traps.
5. **Absence of User History & Comparative Analysis:** Users cannot track their historical threat exposure, compare suspicious variants, or export formal reports.

**ScamLens** resolves these limitations through an integrated, multi-vector architecture combining semantic context analysis, safe non-executing link decomposition, weighted heuristic risk scoring, and interactive cybersecurity intelligence.

---

## 3. Technology Stack

### Backend (100% Pure Java — Zero Python)
- **Programming Language:** Java 17 / Java 21 LTS
- **Core Framework:** Spring Boot 3.3.4
- **Web Layer:** Spring Web MVC
- **Security:** Spring Security 6 with BCrypt password hashing, session concurrency controls, and ownership authorization
- **Persistence Layer:** Spring Data JPA & Hibernate ORM
- **Validation:** Jakarta Validation (Bean Validation)
- **PDF Generation:** OpenPDF 1.3.40 (Pure Java PDF rendering)
- **Build & Dependency Management:** Apache Maven 3.9+

### Frontend
- **Design Language:** Modern Dark Cybersecurity Theme (Deep Navy `#070d1e`, Cyan `#00f0ff`, Electric Blue `#38bdf8`, Purple `#8b5cf6`)
- **Structure & Templating:** HTML5, CSS3, Thymeleaf 3 Template Engine
- **Client Scripting:** JavaScript (ES6+) with Asynchronous REST API Fetch
- **Component Framework:** Bootstrap 5.3
- **Data Visualization:** Chart.js 4.4 (Dynamic rendering from user DB records)
- **Iconography:** Font Awesome 6.5

### Database
- **Primary Relational Database:** MySQL 8.x
- **Development & Testing Database:** H2 in-memory & file engine

### Automated Testing
- JUnit 5 (Jupiter)
- Mockito
- Spring Boot Test & MockMvc

---

## 4. System Architecture

ScamLens adheres to a clean layered architecture with strict separation of concerns:

```
D:\ScamLens\
├── pom.xml                                    # Maven Build Configuration
├── database.sql                               # MySQL 8.x Database Schema & Seeds
├── README.md                                  # Comprehensive System Documentation
├── run.bat                                    # One-click Windows Startup Script
├── test.bat                                   # Automated Test Execution Script
│
├── src\main\java\com\scamlens\
│   ├── ScamLensApplication.java              # Main Spring Boot Application Entry Point
│   │
│   ├── config\
│   │   ├── SecurityConfig.java               # Spring Security 6, BCrypt, Filter Chains
│   │   └── WebConfig.java                    # WebMvc & Static Resource Routing
│   │
│   ├── model\
│   │   ├── User.java                         # User Entity with BCrypt Hashing
│   │   ├── Scan.java                         # Scan Entity with Foreign Key Relationship
│   │   ├── ScamIndicator.java                # Threat Indicator Model with Weights
│   │   ├── UrlFinding.java                   # Passive URL Inspection Finding Model
│   │   └── AnalysisResult.java               # In-Memory Analysis Carrier
│   │
│   ├── repository\
│   │   ├── UserRepository.java               # User JPA Repository
│   │   └── ScanRepository.java               # Scan JPA Repository with Filter Queries
│   │
│   ├── analyzer\
│   │   ├── MessageAnalyzer.java              # Lexical, Uppercase & Punctuation Analyzer
│   │   ├── ContextAnalyzer.java              # Grammatical Negation & Request Intent Engine
│   │   ├── ScamCategoryAnalyzer.java         # Heuristic Threat Detector
│   │   ├── UrlAnalyzer.java                  # Passive Zero-Execution Link Inspector
│   │   ├── TamilScamDictionary.java          # Bilingual 16-Category Cyber Lexicon & Glossary
│   │   ├── TamilTextNormalizer.java          # Tamil Unicode Normalizer & Sentence Tokenizer
│   │   ├── TamilCredentialDetector.java      # Tamil Credential & Intent Identifier
│   │   ├── TamilActionDirectiveDetector.java # Action Directive & Coercion Detector
│   │   ├── TamilNegationDetector.java        # Context-Aware Negation & Intent Classifier
│   │   └── TamilScamAnalyzer.java            # Comprehensive Tamil Semantic Threat Analyzer
│   │
│   ├── service\
│   │   ├── UserService.java                  # User Registration & Profile Management
│   │   ├── ScanService.java                  # Bilingual Persistence & User-Level Authorization
│   │   ├── ScamDetectionService.java         # Central Orchestration Service (English & Tamil)
│   │   ├── TamilLanguageDetectionService.java# Script-Level Tamil & Multilingual Detection
│   │   ├── TamilRiskScoringService.java      # Calibrated Tamil Risk Scoring & Category Caps
│   │   ├── UrlAnalysisService.java           # Passive URL Coordination
│   │   ├── RiskScoringService.java           # Weighted Scoring & Category Caps
│   │   ├── RecommendationService.java        # Bilingual Contextual Guidance (English & Tamil)
│   │   ├── DashboardService.java             # Database Analytics Aggregator
│   │   ├── ReportService.java                # OpenPDF Incident Report Generator
│   │   └── DemoService.java                  # Demonstration Suite
│   │
│   ├── controller\
│   │   ├── HomeController.java               # Landing Page Controller
│   │   ├── AuthController.java               # Sign In, Registration & Session Controller
│   │   ├── DashboardController.java          # Analytics Dashboard & Stats REST API
│   │   ├── ScannerController.java            # Message Scanner & /api/analyze Endpoint
│   │   ├── ComparisonController.java         # ScamLens Compare & /api/compare Endpoint
│   │   ├── HistoryController.java            # History & Secure Deletion REST APIs
│   │   ├── AwarenessController.java          # Scam Intelligence Center
│   │   ├── ProfileController.java            # Profile Settings & Credentials Update
│   │   ├── ReportController.java             # PDF Report Download Controller
│   │   └── DemoController.java               # Demo Suite Controller & REST Endpoints
│   │
│   ├── dto\
│   │   ├── LoginRequest.java                 # Login Request DTO
│   │   ├── RegisterRequest.java              # Registration Request DTO
│   │   ├── ScanRequest.java                  # Message Scan Request (10k max chars)
│   │   ├── ScanResponse.java                 # Structured Scan Findings Response
│   │   ├── ComparisonRequest.java            # Dual Message Comparison Request
│   │   ├── ComparisonResponse.java           # Comparative Breakdown Response
│   │   ├── DashboardStatsDto.java            # User Dynamic Statistics DTO
│   │   ├── UserProfileDto.java               # Profile Management DTO
│   │   └── ApiResponse.java                  # Generic JSON Envelope DTO
│   │
│   ├── exception\
│   │   ├── GlobalExceptionHandler.java       # Centralized REST Error Handler
│   │   ├── ResourceNotFoundException.java    # 404 Entity Exception
│   │   ├── UnauthorizedAccessException.java  # 403 Ownership Authorization Exception
│   │   └── ValidationException.java          # 400 Domain Rule Exception
│   │
│   └── util\
│       └── InputSanitizer.java               # XSS Prevention & Text Truncation Utility
│
├── src\main\resources\
│   ├── application.properties                # Primary MySQL Configuration
│   ├── application-h2.properties             # Standalone H2 Profile Configuration
│   │
│   ├── static\
│   │   ├── css\styles.css                    # Professional Cybersecurity Theme
│   │   └── js\
│   │       ├── main.js                       # UI Utilities, Alerts & Clipboard
│   │
│   └── templates\
│       ├── index.html                        # Landing Page
│       ├── login.html                        # User Authentication Sign In
│       ├── register.html                     # User Account Registration
│       ├── dashboard.html                    # Dynamic Analytics Dashboard (Chart.js)
│       ├── scanner.html                      # Real-Time Message Scanner
│       ├── result.html                       # Comprehensive Incident Report
│       ├── history.html                      # User-Authorized Scan History
│       ├── comparison.html                   # ScamLens Compare (Dual Analysis)
│       ├── awareness.html                    # Scam Intelligence Center (10 Modules)
│       ├── profile.html                      # Account Profile & Password Settings
│       ├── about.html                        # Platform Architecture & Methodology
│       ├── demo.html                         # 12-Scenario Demonstration Suite
│       └── fragments\
│           ├── navbar.html                   # Reusable Navigation Fragment
│           └── footer.html                   # Reusable Footer Fragment
│
└── src\test\
    ├── resources\application-test.properties # Isolated In-Memory H2 Test Configuration
    └── java\com\scamlens\
        ├── analyzer\
        │   ├── MessageAnalyzerTest.java      # Lexical Unit Tests
        │   ├── ContextAnalyzerTest.java      # Negation & Request Intent Tests
        │   ├── ScamCategoryAnalyzerTest.java # 7-Category Detection Tests
        │   └── UrlAnalyzerTest.java          # Passive Link Inspection Tests
        ├── service\
        │   ├── RiskScoringServiceTest.java   # Scoring, Boundary & Cap Tests
        │   ├── ScamDetectionServiceTest.java # Full Orchestration Tests
        │   ├── ReportServiceTest.java        # OpenPDF Header & Generation Tests
        │   └── UserServiceTest.java          # Registration & BCrypt Tests
        ├── repository\
        │   └── ScanRepositoryTest.java       # JPA User Isolation & Stats Tests
        └── controller\
            ├── ScannerApiControllerTest.java # MockMvc /api/analyze Tests
            ├── ComparisonApiControllerTest.java # MockMvc /api/compare Tests
            └── HistoryApiControllerTest.java # MockMvc 403 Forbidden Security Tests
```

---

## 5. Scam Category Taxonomy

The Java detection engine classifies messages across seven threat categories:

| Category | Description | Primary Indicators Triggered | Weight |
|---|---|---|:---:|
| **Phishing** | Deceptive lures designed to collect credentials or account identities | *"verify your account"*, *"unusual login attempt"*, *"confirm your identity"*, *"click link to login"* | 25 |
| **OTP & Credential Theft** | Direct harvest of critical authentication secrets | *"share your OTP"*, *"enter your password"*, *"forward code"*, *"CVV"*, *"ATM PIN"* | 30 |
| **Financial Fraud** | Unsolicited payment demands, crypto doublers, or advance fees | *"send money"*, *"clearance fee"*, *"double your money"*, *"crypto investment"*, *"wire transfer"* | 25 |
| **Lottery & Prize Scams** | Bogus sweepstakes notifications requiring fees before disbursement | *"you have won"*, *"lottery winner"*, *"claim your prize"*, *"selected in lucky draw"* | 20 |
| **Fake Job Scams** | Fraudulent recruitment schemes requiring registration or training fees | *"work from home earn 5000/day"*, *"part-time job offer"*, *"pay registration fee for job"* | 25 |
| **Impersonation** | Posing as banks, couriers (DHL, FedEx), government, or tech support | *"parcel on hold"*, *"package delivery failed"*, *"Netflix suspended"*, *"income tax refund"* | 15 |
| **Urgency & Threats** | Coercive pressure manufactured to provoke rash compliance | *"within 24 hours"*, *"account will be blocked"*, *"immediate action required"*, *"legal action"* | 10 |

---

## 6. Context-Aware Detection Engine

Unlike simplistic string search tools, ScamLens implements **Contextual Semantic Parsing**:

### Negation Handling Example
- **Scenario A (Security Warning):**  
  `"Alert from State Bank: Never share your OTP, password, or CVV with anyone. Bank will never ask for credentials."`  
  *Engine Evaluation:* The `ContextAnalyzer` detects strong negation prefixes (`never share`, `will never ask for`). The message is marked as an **Official Security Advisory** with near-zero risk score (**5/100, Low Risk**).
- **Scenario B (Active Harvest Attack):**  
  `"Your account is locked. Share your OTP immediately to verify your account."`  
  *Engine Evaluation:* The `ContextAnalyzer` detects active request intent (`share your OTP`) combined with manufactured urgency (`immediately`). The message is flagged as **Critical Threat (85/100)**.

---

## 7. Safe Passive URL Analysis Engine

ScamLens utilizes Java's built-in `java.net.URI` and `java.net.IDN` libraries to perform **passive, non-executing link decomposition**:
- **Zero-Execution Guarantee:** ScamLens never sends HTTP requests to suspicious URLs, never downloads attachments, and never executes JavaScript from target domains.
- **Shortener Unmasking:** Identifies obfuscating shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, `cutt.ly`, etc.).
- **Direct IP Host Identification:** Flags bare IP addresses (`http://192.168.1.55/login`).
- **Deceptive User-Info Syntax:** Identifies `@` redirection syntax (`https://paypal.com@badsite.ru/login`).
- **Punycode / IDN Spoofing:** Flags internationalized homograph deception (`xn--pypal-4ve.com`).
- **Excessive Subdomain Depth:** Detects multi-level brand mimicking (`login.secure.bank.update.xyz.com`).
- **Suspicious TLD Detection:** Analyzes high-abuse top-level domains (`.xyz`, `.top`, `.tk`, `.buzz`, `.click`).
- **Insecure Protocol Warning:** Identifies unencrypted HTTP links.

---

## 8. Weighted Risk Scoring Algorithm

```
Total Risk Score = MIN( 100, SUM( MIN(CategoryScore, CategoryCap) ) + UrgencyBonus )
```

### Risk Level Boundaries

| Score Range | Classification | Color Badge | System Recommended Action |
|:---:|:---:|:---:|---|
| **0 – 24** | **Low Risk** | Green | Exercise routine digital hygiene; confirm unexpected requests via official channels. |
| **25 – 49** | **Medium Risk** | Amber / Yellow | Heightened caution; verify sender identity directly before responding. |
| **50 – 74** | **High Risk** | Orange | Dangerous indicators present; do not click embedded links or disclose personal info. |
| **75 – 100** | **Critical Threat** | Red | Immediate threat; block sender, delete communication, freeze credentials if entered. |

> **Heuristic Disclaimer:** The ScamLens Risk Score is an algorithmic heuristic risk indicator designed to evaluate suspicious patterns and warning signs. It does not constitute a mathematical guarantee or legal certainty. A low score does not guarantee absolute safety, and a high score does not conclusively prove criminal activity.

---

## 9. Platform Modules

### 1. Landing Page (`/`)
- Brand identity with tagline: *"Think Before You Click. Stay Ahead of Scams."*
- Hero section: *"Detect Scams Before They Reach You."*
- Dual-vector scanning introduction (Message NLP & Safe URL analysis).
- How It Works 3-step workflow.
- Global cybersecurity statistics counter.
- Direct navigation call-to-actions.

### 2. User Authentication (`/login`, `/register`)
- Secured with **Spring Security 6**.
- Password hashing with **BCrypt**.
- Duplicate email prevention and format validation.
- Pre-seeded test credentials: `demo@scamlens.com` / `password123`.

### 3. Real-Time Message Scanner (`/scanner`)
- Accepts SMS, WhatsApp, Email, Social Media, or URLs.
- Input capacity up to **10,000 characters** with dynamic character counter.
- Asynchronous AJAX communication with `/api/analyze` (no page reloads).
- Instant risk score gauge, threat indicators table, and safety recommendations.
- Direct link to PDF export.

### 4. ScamLens Compare (`/compare`)
- Input two independent messages simultaneously.
- Analyzes both messages independently through the Java engine.
- Renders side-by-side risk score circles, category tags, and URL findings.
- Calculates exact risk score delta and identifies structural differences.
- Enforces the **Cautionary Principle**: The lower-scoring message is never automatically classified as safe.

### 5. Private Scan History (`/history`)
- Real-time client-side search across message text.
- Filter by Risk Level (Critical, High, Medium, Low).
- Filter by Scam Category.
- Direct links to View Report (`/result/{id}`) or Download PDF (`/api/report/{id}/pdf`).
- Single-click record deletion with confirmation.
- **Strict User Authorization:** Backend verifies scan ownership (`Scan.user.id == User.id`), returning `403 Forbidden` if another user's ID is requested.

### 6. Interactive Analytics Dashboard (`/dashboard`)
- Real statistics calculated directly from the logged-in user's database records:
  1. Total Scans executed
  2. Critical Risk Scans (75–100)
  3. High Risk Scans (50–74)
  4. Medium Risk Scans (25–49)
  5. Average Risk Score
- **Dynamic Chart.js Visualizations:**
  - Doughnut Chart: Risk Level Breakdown (Low, Med, High, Critical)
  - Bar Chart: Threat Categories Encountered
- Dynamic Security Insights derived from user activity.
- Recent scans summary table.

### 7. Downloadable PDF Incident Reports (`/api/report/{id}/pdf`)
- Engineered with **OpenPDF** in pure Java.
- Styled header with ScamLens cybersecurity branding.
- Risk classification badge with dynamic color coding.
- Formatted tables for submitted message, threat indicators, and URL findings.
- Bulleted safety action items and official heuristic disclaimer.

### 8. Scam Intelligence Center (`/awareness`)
Comprehensive educational curriculum covering **10 essential topics**:
1. What is Phishing?
2. How OTP Scams Work
3. How Fake Job Scams Work
4. How Lottery Scams Work
5. How to Identify Suspicious URLs
6. How Impersonation Scams Work
7. How to Identify Fake Payment Requests
8. How to Protect Personal Information
9. What to Do After Receiving a Suspicious Message
10. Basic Cybersecurity Safety Practices

Each topic features key warning signs, attack anatomy examples, and defensive protocols.

### 9. Account Profile Management (`/profile`)
- Displays user legal name, registered email, account creation date, and total scans.
- Form to update display name.
- Form to change password with current password verification and length validation.

### 10. Demonstration Suite (`/demo`)
- 12 pre-loaded realistic scenarios covering all 7 scam categories, legitimate warnings, and normal messages.
- *"Run Java Engine"* button executes live `/api/demo/analyze/{id}` analysis.
- Modal displays dynamic score, categories, phrases, and safety advice.

---

## 10. REST API Specification

| Endpoint | Method | Security | Description |
|---|:---:|:---:|---|
| `/api/auth/register` | `POST` | Public | Register a new user account |
| `/api/auth/login` | `POST` | Public | Authenticate and initiate session |
| `/api/auth/logout` | `POST` | Public | Invalidate current user session |
| `/api/analyze` | `POST` | Public / Auth | Analyze message; saves to DB if authenticated |
| `/api/compare` | `POST` | Public | Compare two messages side by side |
| `/api/demo/samples` | `GET` | Public | Retrieve all 12 demo scenarios |
| `/api/demo/analyze/{id}`| `POST` | Public | Run Java engine on specific demo scenario |
| `/api/dashboard/stats` | `GET` | Authenticated | Retrieve user-specific aggregated statistics |
| `/api/dashboard/recent-scans` | `GET` | Authenticated | Retrieve recent scans for logged-in user |
| `/api/history` | `GET` | Authenticated | Search & filter user scan history |
| `/api/history/{id}` | `GET` | Authenticated | Retrieve single scan (User ownership verified) |
| `/api/history/{id}` | `DELETE`| Authenticated | Delete single scan (User ownership verified) |
| `/api/report/{id}/pdf` | `GET` | Authenticated | Download OpenPDF incident report |
| `/api/profile` | `GET` | Authenticated | Retrieve user profile metrics |
| `/api/profile` | `PUT` | Authenticated | Update user name or change password |

---

## 11. Windows Setup and Execution Guide

### Software Prerequisites
1. **Java JDK 17 or 21 LTS** (Installed and added to system `PATH`).
2. **Apache Maven 3.9+** (Installed and added to system `PATH`).
3. **MySQL Server 8.x** (Running on port 3306).

---

### Step 1: MySQL Database Initialization

Open MySQL Workbench or your terminal and execute `database.sql`:

```sql
CREATE DATABASE IF NOT EXISTS scamlens
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE scamlens;

-- Run the complete database.sql script included in project root
```

*Or via PowerShell:*
```powershell
& "C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe" -u root -p < D:\ScamLens\database.sql
```

---

### Step 2: Database Configuration

In `D:\ScamLens\src\main\resources\application.properties`:
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/scamlens?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC
spring.datasource.username=root
spring.datasource.password=YOUR_MYSQL_PASSWORD
```

*Alternatively, set environment variables without editing the file:*
```powershell
$env:DB_USERNAME="root"
$env:DB_PASSWORD="YOUR_MYSQL_PASSWORD"
```

---

### Step 3: Build ScamLens

In PowerShell or Command Prompt:

```powershell
cd D:\ScamLens
mvn clean install
```

This compiles all 47 Java classes, runs the 51 automated tests, and packages `target/scamlens.jar`.

---

### Step 4: Run ScamLens

**Option A: Using Maven**
```powershell
mvn spring-boot:run
```

**Option B: Using Packaged Runnable JAR (Production Style)**
```powershell
java -jar target/scamlens.jar
```

**Option C: Zero-Dependency Standalone Mode (H2 File Database)**
If you want to run ScamLens immediately without starting a local MySQL server:
```powershell
java -jar target/scamlens.jar --spring.profiles.active=h2
```

**Option D: One-Click Startup Script**
Double-click `D:\ScamLens\run.bat` in Windows Explorer.

---

### Step 5: Access the Web Application

Open your browser and navigate to:

```
http://localhost:8080
```

### Pre-Seeded Demonstration Credentials

| Role | Email | Password |
|---|---|---|
| **Security Analyst** | `demo@scamlens.com` | `password123` |

---

## 12. Automated Test Suite

ScamLens includes **51 comprehensive automated test cases** executed with JUnit 5, Mockito, and Spring Boot Test:

```
-------------------------------------------------------
 T E S T S
-------------------------------------------------------
Running com.scamlens.analyzer.ContextAnalyzerTest
Tests run: 4, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.analyzer.MessageAnalyzerTest
Tests run: 5, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.analyzer.ScamCategoryAnalyzerTest
Tests run: 9, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.analyzer.UrlAnalyzerTest
Tests run: 9, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.controller.ComparisonApiControllerTest
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.controller.HistoryApiControllerTest
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.controller.ScannerApiControllerTest
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.repository.ScanRepositoryTest
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.service.ReportServiceTest
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.service.RiskScoringServiceTest
Tests run: 6, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.service.ScamDetectionServiceTest
Tests run: 5, Failures: 0, Errors: 0, Skipped: 0
Running com.scamlens.service.UserServiceTest
Tests run: 4, Failures: 0, Errors: 0, Skipped: 0

Results:
Tests run: 51, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

To execute the test suite at any time:
```powershell
mvn test
```

---

## 13. Security & Privacy Safeguards

- **No Plaintext Passwords:** Passwords hashed with BCrypt (10 rounds).
- **Strict Data Isolation:** Scans belong exclusively to the authenticated user. User A cannot view or delete User B's records by manipulating IDs in URL paths or API requests (`UnauthorizedAccessException` throws `403 Forbidden`).
- **Non-Executing Link Inspection:** URLs are parsed exclusively through URI string decomposition and IDN parsing. Zero network sockets connect to target hosts.
- **Sensitive Data Minimization:** Passwords, OTPs, or CVVs contained in scanned messages are never stored in user credential columns.
- **Input Sanitization:** Multi-stage XSS sanitization and null character removal prevent injection attacks.
- **Input Length Restrictions:** Max 10,000 characters enforced at both frontend and backend validation layers.

---

## 14. Known Limitations

- **Passive Link Inspection Boundary:** ScamLens intentionally does not fetch live HTML from target URLs to ensure user safety. If an attacker hosts an attack on a completely unblemished, freshly registered domain without brand keywords or suspicious parameters, passive inspection classifies it as Low Risk. Live sandbox detonate analysis is outside the passive scope.
- **Natural Language Nuances:** While the context engine handles standard negation (*"never share"*, *"bank will not ask"*), complex sarcastic or idiomatic slang may occasionally evade keyword intent detection.

---

## 15. License

This project is licensed under the MIT License - see the `LICENSE` file for details.
