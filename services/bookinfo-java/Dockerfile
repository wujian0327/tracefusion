FROM trace-fusion-bookinfo-reviews:extended

WORKDIR /app
COPY target/bookinfo-java-1.0.0.jar /app/bookinfo-java.jar

ENV SERVER_PORT=9080
EXPOSE 9080

ENTRYPOINT ["java", "-jar", "/app/bookinfo-java.jar"]
