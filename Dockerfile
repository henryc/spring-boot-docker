# Build stage
FROM public.ecr.aws/docker/library/maven:3.8.5-jdk-8-slim AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean install

FROM amazoncorretto:8-alpine-jdk
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring
ARG JAR_FILE=target/*.jar
COPY --chown=spring:spring --from=builder /app/${JAR_FILE} spring-boot-docker-demo.jar
HEALTHCHECK --interval=5m --timeout=3s CMD curl -f http://localhost:8080/actuator/health/ || exit 1
EXPOSE 8080
ENTRYPOINT ["java","-jar","/spring-boot-docker-demo.jar"]