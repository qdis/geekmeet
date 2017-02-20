FROM java:8-jre
MAINTAINER Timo Bejan <timo.bejan@gmail.com>

VOLUME /tmp

ADD admin-service.jar /app/

CMD ["java", "-Xmx750m", "-jar", "/app/admin-service.jar"]

EXPOSE 5030