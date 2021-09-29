FROM jboss/keycloak:14.0.0
COPY session-limiter/target/session-limiter-1.0-SNAPSHOT.jar /opt/jboss/keycloak/standalone/deployments/
