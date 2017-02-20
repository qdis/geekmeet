FROM java:8-jre
MAINTAINER Timo Bejan <timo.bejan@gmail.com>

VOLUME /tmp

ADD service-registry.jar /app/

CMD ["java", "-Xmx500m", "-jar", "/app/service-registry.jar"]

EXPOSE 8761