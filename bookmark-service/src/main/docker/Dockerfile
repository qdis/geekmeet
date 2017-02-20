FROM java:8-jre
MAINTAINER Timo Bejan <timo.bejan@gmail.com>

VOLUME /tmp

ADD bookmark-service.jar /app/

CMD ["java", "-Xmx750m", "-jar", "/app/bookmark-service.jar"]

EXPOSE 5010