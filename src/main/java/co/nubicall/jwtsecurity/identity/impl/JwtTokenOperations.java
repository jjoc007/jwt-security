package co.nubicall.jwtsecurity.identity.impl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.util.Date;
import java.util.Map;

import co.nubicall.jwtsecurity.identity.TokenOperations;
import co.nubicall.jwtsecurity.identity.UserAccessToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtTokenOperations implements TokenOperations {

    @Value("${jwt.token.basic.signing.secret:123}")
    private String secret;

    @Value("${jwt.token.basic.signing.keyalias:adlauthkey}")
    private String keyalias;

    @Value("${jwt.token.basic.signing.keytool:adlauthkey.jks}")
    private String keytool;

    @Value("${jwt.token.expiration.seconds:1800}")
    private int expiration;

    @Override
    public UserAccessToken generateToken(String username, Map<String, Object> additionalInfo) {

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        // Let's set the JWT Claims
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
        long tokenExpiresIn = nowMillis + expiration * 1000;
        JwtBuilder builder = Jwts.builder().setId(username)
                .setIssuedAt(now)
                .setSubject("ADL JWT Token")
                .setIssuer("Nubicall")
                .setExpiration(new Date(tokenExpiresIn))
                .addClaims(additionalInfo);

        String jwtToken = builder.compact();

        UserAccessToken accessToken = new UserAccessToken(username, jwtToken, tokenExpiresIn);
        return accessToken;
    }

}