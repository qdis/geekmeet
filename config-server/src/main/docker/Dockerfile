FROM java:8-jre
MAINTAINER Timo Bejan <timo.bejan@gmail.com>

VOLUME /tmp

ADD config-server.jar /app/

CMD ["java", "-Xmx200m", "-jar", "/app/config-server.jar"]

EXPOSE 8888