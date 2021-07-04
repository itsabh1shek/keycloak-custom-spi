package com.itsabhishek.keycloak;

public class Constants {
    public static final String DISPLAY_TYPE = "User Session Limiter";
    public static final String USER_REALM_LIMIT = "userRealmLimit";
    public static final String USER_REALM_LIMIT_LABEL = "Maximum concurrent sessions for a user in a realm";
    public static final String ACTION = "action";
    public static final String ACTION_LABEL = "Action when user session limit is exceeded";
    public static final String DENY_NEW_SESSION = "Deny new session";
    public static final String TERMINATE_OLDEST_SESSION = "Terminate oldest session";
    public static final String LIMIT_USER_SESSION = "limitUserSession";
    public static final String DENY_NEW_SESSION_ERROR_MESSAGE = "User already logged-in. Logout first and try again.";

}
