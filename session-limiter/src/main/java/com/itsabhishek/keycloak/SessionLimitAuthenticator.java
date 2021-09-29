package com.itsabhishek.keycloak;


import org.apache.commons.lang.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.core.Response;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.Stream;

public class SessionLimitAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(SessionLimitAuthenticator.class);
    private String action;
    private final KeycloakSession keycloakSession;

    public SessionLimitAuthenticator(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        AuthenticatorConfigModel configModel = authenticationFlowContext.getAuthenticatorConfig();
        action = configModel.getConfig().get(Constants.ACTION);
        logger.info("action : "+action);
        UserModel userModel = authenticationFlowContext.getUser();
        if(userModel != null && action != null) {
            logger.info("current user: " + userModel.getUsername());
            long limit = Long.parseLong(configModel.getConfig().get(Constants.USER_REALM_LIMIT));
            logger.info("limit: " + limit);
            long existingSessionCount = keycloakSession.sessions().getUserSessionsStream(authenticationFlowContext.getRealm(), userModel).count();
            logger.info("existing session count: " + existingSessionCount);
            if (limitExceeds(limit, existingSessionCount)) {
                logger.info("exceeded session limit");
                handleExceededLimit(authenticationFlowContext);
            } else {
                authenticationFlowContext.success();
            }
        } else {
            authenticationFlowContext.success();
        }
    }

    private void handleExceededLimit(AuthenticationFlowContext authenticationFlowContext) {
        switch (action){
            case Constants.DENY_NEW_SESSION:
                logger.info("denying new session");
                Response challengeResponse = authenticationFlowContext.form().setError(Constants.DENY_NEW_SESSION_ERROR_MESSAGE).createErrorPage(Response.Status.FORBIDDEN);
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CLIENT_SESSION, challengeResponse);
                break;
            case Constants.TERMINATE_OLDEST_SESSION:
                logger.info("terminating oldest session");
                logoutOldestSession(authenticationFlowContext);
                authenticationFlowContext.success();
                break;
        }
    }

    private void logoutOldestSession(AuthenticationFlowContext authenticationFlowContext) {
        Stream<UserSessionModel> userSessions = keycloakSession.sessions().getUserSessionsStream(authenticationFlowContext.getRealm(), authenticationFlowContext.getUser());
        Optional<UserSessionModel> oldest = userSessions.min(Comparator.comparingInt(UserSessionModel::getStarted));
        oldest.ifPresent(userSession -> AuthenticationManager.backchannelLogout(keycloakSession, userSession, true));
    }

    private boolean limitExceeds(long limit, long existingSessionCount) {
        return limit > 0 && existingSessionCount > limit - 1;
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }
}
