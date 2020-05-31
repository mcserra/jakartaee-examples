FROM adoptopenjdk/openjdk11:alpine-slim

WORKDIR /opt/payara
ENV INSTALL_DIR /opt/payara
ENV PAYARA_ARCHIVE payara-micro.jar

RUN mkdir -p $INSTALL_DIR/deployments && \
 apk update && \
 apk add curl

ENV PAYARA_PKG "https://repo1.maven.org/maven2/fish/payara/extras/payara-micro/5.194/payara-micro-5.194.jar"

#download payara-micro to folder
RUN curl -o $INSTALL_DIR/$PAYARA_ARCHIVE $PAYARA_PKG

ENV PAYARA_HOME ${INSTALL_DIR}
ENV DEPLOYMENT_DIR ${PAYARA_HOME}

ENV DEPLOY_DIR $INSTALL_DIR/deployments

# war to directory
COPY ./target/jwt.war $DEPLOY_DIR

EXPOSE 8080

# Use tini as PID1 to avoid p
RUN apk add --no-cache tini
# Tini is now available at /sbin/tini
ENTRYPOINT ["/sbin/tini", "--"]

CMD ["java", "-jar", "payara-micro.jar", "--nocluster", "--deploy", "deployments/jwt.war"]
