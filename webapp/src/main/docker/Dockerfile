FROM java:8-jre
MAINTAINER Timo Bejan <timo.bejan@gmail.com>

VOLUME /tmp

ADD webapp.jar /app/

CMD ["java", "-Xmx500m", "-jar", "/app/webapp.jar"]

EXPOSE 8761