# spring-boot-docker
This project is used to containerize and deploy a Spring Boot sample application to [AWS Fargate](https://aws.amazon.com/fargate/) using [AWS Copilot CLI](https://github.com/aws/copilot-cli).

### Prerequisites
The following items should be installed in your system:
* Java 8 or newer (full JDK not a JRE).
* git command line tool (https://help.github.com/articles/set-up-git)
* Your preferred IDE 
  * Eclipse with the m2e plugin. Note: when m2e is available, there is an m2 icon in `Help -> About` dialog. If m2e is not there, just follow the install process here: https://www.eclipse.org/m2e/
  * [Spring Tools Suite](https://spring.io/tools) (STS)
  * IntelliJ IDEA
  * [VS Code](https://code.visualstudio.com)
* [Docker Desktop](https://www.docker.com/products/docker-desktop)
* [AWS Copilot CLI](https://github.com/aws/copilot-cli/releases)
* [AWS Account](https://aws.amazon.com/free/)

### SAML configurations
This applications already has Service Provider (SP)'s private key / cert and Identity Provider (IdP)'s metadata included within this POC (for teaching purposes).

application.yml hold the configurations ( above info, entityId, etc )

SecurityConfig.java holds the programmatic setup for SAML.

To change Identity Provider (IdP) like UCLA's IdP, replace identity-provider-certificate.crt.

To generate SP service provider key and certificate, run following command and replace private.key and public.cer:

```
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout private.key -out public.cer
```


## Running locally

The Spring Quickstart Guide is a [Spring Boot](https://spring.io/quickstart) application built using [Maven](https://spring.io/guides/gs/maven/). You can build a jar file and run it from the command line (it should work just as well with Java 8, 11 or 17):

```
git clone https://github.com/henryc/spring-boot-docker.git
cd spring-boot-docker
mvn clean package
mvn spring-boot:run
```

You can then access the spring boot application here: 
* http://localhost:8080/hello
* http://localhost:8080/actuator/health
* http://localhost:8080/detail (for SSO sign-in process)


## Building and tagging the Container

```
docker build -t springio/spring-boot-docker .
```
## Running the Container

```
docker run -p 8080:8080 springio/spring-boot-docker
```

## Other useful Docker commands

```
# List all the locally stored docker images
docker images
# List all the containers
docker ps
# Stop a running container
docker stop <container_id or container_name>
# Remove a stopped container
docker rmi <image_id>
```

## Dockerizing the sample spring boot app using Dockerfile

```
FROM public.ecr.aws/docker/library/maven:3.8.5-amazoncorretto-8 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package

FROM public.ecr.aws/docker/library/amazoncorretto:8u332-alpine3.15-jre
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring
ARG JAR_FILE=target/*.jar
COPY --chown=spring:spring --from=builder /app/${JAR_FILE} spring-boot-docker-demo.jar
HEALTHCHECK --interval=5m --timeout=3s CMD curl -f http://localhost:8080/actuator/health/ || exit 1
EXPOSE 8080
ENTRYPOINT ["java","-jar","/spring-boot-docker-demo.jar"]
```

## Deploying the container on existing infrastructure with AWS Copilot CLI to AWS Fargate

1. Create a new application with an existing domain name in Amazon Route53 using [copilot app init](https://aws.github.io/copilot-cli/docs/commands/app-init/) command.
```
copilot app init --domain <domain_name>
``` 

2. Create new application using [copilot init](https://aws.github.io/copilot-cli/docs/commands/init/) command.
```
copilot init
```
**NOTE:** When prompted if you would like to deploy a test environment? Enter **N**. So that you can specify your own existing VPC resources using [copilot env init](https://aws.github.io/copilot-cli/docs/commands/env-init/) command.

3. Creates a test environment with imported VPC resources
```
copilot env init --name test --profile default --app <app-name> --import-vpc-id <vpc-id> \
--import-public-subnets <public-subnet-id-a, public-subnet-id-b> \
--import-private-subnets <private-subnet-id-a, private-subnet-id-b>
``` 

**IMPORTANT:** Before deploying the service update the copilot/your-service-name/manifest.yml file to include the correct path to the [load balanced web service](https://aws.github.io/copilot-cli/docs/manifest/lb-web-service/) healthcheck as shown below:
```
path: '/actuator/health/'
```
By default, AWS Fargate cluster tasks are hosted in public subnets. However, If you want to place them into your private subnets, add the following to the manifest.yml file:
```
network:
  vpc:
    placement: 'private'
```
4. Deploys the service using [copilot deploy](https://aws.github.io/copilot-cli/docs/commands/deploy/) command
```
copilot deploy
```
Once the service is deployed, you can access the sample service at your ALB over the internet.

**IMPORTANT:** Before copilot deploy, uncomment acs.location for AWS env (one with https) in application.yml

5. Verify the service endpoints using cURL command. You should get similar output as follows:
```
$ curl -X GET ALB/actuator/health
{"status":"UP"}
$ curl -X GET ALB/hello
Hello World!
$ curl -X GET ALB/hello?name=Docker
Hello Docker!
```
**HINT:** Append the service endpoint to the ALB.

6. Verify SSO login process (in browser) with following link

```
local: http://localhost:8080/detail
remote: ALB/detail
```
*Note: for AWS environments, please get metadata from ALB/saml2/service-provider-metadata/samlexample
and upload to https://samltest.id/upload.php before testing

7. To clean up and delete all resources associated with the application use [copilot app delete](https://aws.github.io/copilot-cli/docs/commands/app-delete/) command.
```
copilot app delete
```


# Resources
* [Spring Boot with Docker](https://spring.io/guides/gs/spring-boot-docker/)
* [AWS Copilot CLI](https://aws.github.io/copilot-cli/)
* [AWS Copilot CLI Gitter](https://gitter.im/aws/copilot-cli)