# Test case: vulnerable libraries inside a SHARED (fat) jar with relocated packages.
# Direct dependencies: commons-text 1.9, snakeyaml 1.30, slf4j-api 2.0.9 (clean control).
# commons-text 1.9 pulls in commons-lang3 3.11 (transitive). See
# ground-truth/java-shaded-jar-cve.json (written before any scan).
#
# The build stage compiles and shades the jar. `mvn dependency:tree` and the jar listing
# print the evidence into the build log (build with --progress=plain to see it).
# The final stage is the same pinned distroless static base as images/minimal-base-pass:
# no JRE, nothing is run, and the only thing added is the jar.
# Build stage pinned by index digest. Build and scan with --platform=linux/amd64.
FROM maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -B dependency:tree && mvn -B -q package && jar tf target/shaded-java-cve-1.0.jar | grep -E "pom.properties"

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /src/target/shaded-java-cve-1.0.jar /app/app.jar
