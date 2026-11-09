@echo off
title Build ScamLens - Maven Package
cls
echo =====================================================================
echo  Building ScamLens Platform with Maven...
echo =====================================================================
echo.
mvn clean package
echo.
echo Build process complete. Runnable JAR located at target\scamlens.jar
pause
