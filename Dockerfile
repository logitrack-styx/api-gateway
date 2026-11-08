# Etapa 1: compilación de la aplicación.
FROM eclipse-temurin:25-jdk AS build

WORKDIR /app

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

RUN chmod +x mvnw && ./mvnw -q dependency:go-offline

COPY src/ src/

RUN ./mvnw -q clean package -DskipTests


# Etapa 2: ejecución de la aplicación.
FROM eclipse-temurin:25-jre

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home appuser

COPY --from=build /app/target/*.jar app.jar

USER appuser

EXPOSE 8066

HEALTHCHECK --interval=10s --timeout=5s --start-period=35s --retries=10 \
  CMD curl --fail --silent http://localhost:8066/actuator/health || exit 1

ARG SOURCE_DIGEST
LABEL org.logitrack.source.sha256=$SOURCE_DIGEST

ENTRYPOINT ["java", "-jar", "app.jar"]
