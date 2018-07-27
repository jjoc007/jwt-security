package co.nubicall.jwtsecurity.identity;

import java.util.Map;

@FunctionalInterface
public interface TokenOperations {

    /**
     * Generates a JWT token with SHA256withRSA.
     * @param username
     * @param additionalInfo claims
     * @return JWT token
     */
    UserAccessToken generateToken(String username, Map<String,Object> additionalInfo);

}
