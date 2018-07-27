package co.nubicall.jwtsecurity.identity.impl;

import java.util.Map;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Class to get the current authentication info.
 */
public class SecurityContextUserAcessor {

    private TokenStore tokenStore;

    public SecurityContextUserAcessor(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    /**
     * Get token value for the current authentication.
     * @return token
     */
    public String getTokenValue() {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) SecurityContextHolder.getContext().getAuthentication().getDetails();
        return details.getTokenValue();
    }

    /**
     * Get the payload associated to the token for the current authentication.
     * @return payload
     */
    public Map<String, Object> getPayload() {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) SecurityContextHolder.getContext().getAuthentication().getDetails();
        final OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(details.getTokenValue());
        Map<String, Object> additionalInfo = accessToken.getAdditionalInformation();
        return additionalInfo;
    }

}