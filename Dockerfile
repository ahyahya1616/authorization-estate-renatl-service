# ----------------------------
# Build stage
# ----------------------------
FROM maven:3.9.6-eclipse-temurin-17 AS build

# Définir le répertoire de travail
WORKDIR /app

# Copier uniquement le pom.xml pour utiliser le cache Docker
COPY pom.xml .

# Télécharger toutes les dépendances Maven (cache efficace)
RUN mvn -B dependency:go-offline

# Copier le code source
COPY src ./src

# Compiler le projet et générer le jar (skip tests pour accélérer CI)
RUN mvn clean package -DskipTests

# ----------------------------
# Runtime stage
# ----------------------------
FROM eclipse-temurin:17-jre-alpine

# Créer un utilisateur non-root pour la sécurité
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Définir le répertoire de travail
WORKDIR /app

# Copier le jar depuis le build stage
COPY --from=build /app/target/*.jar app.jar

# Passer à l’utilisateur non-root
USER appuser

# Variable pour options JAVA
ENV JAVA_OPTS=""

# Lancer l’application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]