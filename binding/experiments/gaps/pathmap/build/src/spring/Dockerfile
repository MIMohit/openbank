# syntax=docker/dockerfile:1
FROM maven:3.10.0-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package && java -version 2>&1 | head -1 > /src/target/java-version.txt

FROM eclipse-temurin:21.0.13_9-jre-noble
WORKDIR /app
COPY --from=build /src/target/app.jar /app/app.jar
ENV FRAMEWORK_TAG=spring OVERRIDE=off VERIFY_MODE=off
EXPOSE 8080
ENTRYPOINT ["java", "-Xmx256m", "-XX:+UseSerialGC", "-jar", "/app/app.jar"]

# W15 ext-routes: ROUTES=v2 enables the richer v1 route space (build :v2 with --build-arg ROUTES=v2).
ARG ROUTES=off
ENV ROUTES=${ROUTES}
