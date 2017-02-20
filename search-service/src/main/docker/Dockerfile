FROM java:8-jre
MAINTAINER Timo Bejan <timo.bejan@gmail.com>

VOLUME /tmp

ADD search-service.jar /app/

CMD ["java", "-Xmx750m", "-jar", "/app/search-service.jar"]

EXPOSE 5020