@echo off
title ScamLens - Intelligent Scam Detection Platform
cls
echo =====================================================================
echo  ScamLens - Intelligent Scam Detection & Cybersecurity Analysis
echo  Tagline: Think Before You Click. Stay Ahead of Scams.
echo =====================================================================
echo.
echo Select Execution Profile:
echo  [1] Primary Profile (MySQL 8.x) - Requires MySQL running on port 3306
echo  [2] Standalone Profile (H2 File Database) - Zero Setup Required
echo.
set /p PROFILE_CHOICE="Enter your choice (1 or 2) [Default: 2]: "

if "%PROFILE_CHOICE%"=="1" (
    echo Starting ScamLens with MySQL Primary Profile...
    java -jar target\scamlens.jar
) else (
    echo Starting ScamLens with H2 Standalone Profile...
    java -jar target\scamlens.jar --spring.profiles.active=h2
)

pause
