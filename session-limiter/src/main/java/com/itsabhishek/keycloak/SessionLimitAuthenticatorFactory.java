package com.itsabhishek.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

import static com.itsabhishek.keycloak.Constants.*;

public class SessionLimitAuthenticatorFactory implements AuthenticatorFactory {

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty realmCountLimit = new ProviderConfigProperty();
        realmCountLimit.setName(USER_REALM_LIMIT);
        realmCountLimit.setLabel(USER_REALM_LIMIT_LABEL);
        realmCountLimit.setType(ProviderConfigProperty.STRING_TYPE);
        ProviderConfigProperty actionProperty = new ProviderConfigProperty();
        actionProperty.setName(ACTION);
        actionProperty.setLabel(ACTION_LABEL);
        actionProperty.setType(ProviderConfigProperty.LIST_TYPE);
        actionProperty.setDefaultValue(DENY_NEW_SESSION);
        actionProperty.setOptions(Arrays.asList(DENY_NEW_SESSION, TERMINATE_OLDEST_SESSION));
        return Arrays.asList(realmCountLimit, actionProperty);
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new SessionLimitAuthenticator(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return LIMIT_USER_SESSION;
    }
}
