# Build stage
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app

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
COPY --from=builder --chown=scamlens:scamlens /app/target/scamlens-*.jar app.jar

# Switch to non-root user
USER scamlens

# Render dynamic port binding and memory constraints for free tier (512MB RAM)
ENV PORT=8080
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Dfile.encoding=UTF-8"

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=${PORT} -jar app.jar"]
