FROM java:8-jre
MAINTAINER Timo Bejan <timo.bejan@gmail.com>

VOLUME /tmp

ADD authorization-service.jar /app/


CMD ["java", "-Xmx500m", "-jar", "/app/authorization-service.jar"]

EXPOSE 5000