# Build stage
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app

ENV MAVEN_OPTS="-Xmx512m -XX:+TieredCompilation -XX:TieredStopAtLevel=1"

# Copy configuration and sources
COPY pom.xml .
COPY src ./src

# Build package skipping tests for fast deployment
RUN mvn clean package -DskipTests=true

# Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Create data directory and non-root user with full ownership
RUN mkdir -p /app/data && \
    addgroup -S scamlens && \
    adduser -S scamlens -G scamlens && \
    chown -R scamlens:scamlens /app

# Copy built artifact with ownership assigned
COPY --from=builder --chown=scamlens:scamlens /app/target/scamlens.jar app.jar

# Switch to non-root user
USER scamlens

# Default to H2 profile unless overridden, bind to Render $PORT, set memory ceiling
ENV PORT=8080
ENV SPRING_PROFILES_ACTIVE=h2
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Dfile.encoding=UTF-8"

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=${PORT:-8080} -Dspring.profiles.active=${SPRING_PROFILES_ACTIVE:-h2} -jar app.jar"]
