FROM java:8-jre
MAINTAINER Timo Bejan <timo.bejan@gmail.com>

VOLUME /tmp

ADD service-gateway.jar /app/

CMD ["java", "-Xmx500m", "-jar", "/app/service-gateway.jar"]

EXPOSE 5020