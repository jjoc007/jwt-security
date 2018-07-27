package co.nubicall.jwtsecurity.identity.impl;


import java.io.IOException;
import java.nio.charset.Charset;

import co.nubicall.jwtsecurity.identity.TokenOperations;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * Extend this class to define a JWT resource server, and override the configure method to define
 * specific rules for authorized and public endpoints.
 * Add the annotations:
 * @EnableAutoConfiguration
 * @EnableResourceServer
 */
public class JwtResourceServer extends ResourceServerConfigurerAdapter {

    @Value("${jwt.token.basic.signing.publickey:adl-publickey.txt}")
    private String publicKey;


    @Override
    public void configure(ResourceServerSecurityConfigurer config) {
        config.tokenServices(this.tokenServices());
    }

    /**
     * @see org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter#configure(org.springframework.security.config.annotation.web.builders.HttpSecurity)
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/swagger-ui.html").permitAll();
        http.authorizeRequests().antMatchers("/swagger-resources/**").permitAll();
        http.authorizeRequests().antMatchers("/**/api-docs").permitAll();
        http.authorizeRequests().antMatchers("/info").permitAll();
        http.authorizeRequests().antMatchers("/health").permitAll();
        http.authorizeRequests().antMatchers("/api/login").permitAll();
        http.authorizeRequests().anyRequest().authenticated();
    }

    /**
     * TokenStore is an implementation that just reads data from the tokens themselves.
     * Not really a store since it never persists anything.
     *
     * @return tokenStore
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(this.accessTokenConverter());
    }

    /**
     * Simple signing using HMAC using SHA-256 algorithm.
     * Strong encryption is at the authorization-server side.
     * @return jwtAccessTokenConverter
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        Resource resource = new ClassPathResource(publicKey);
        String publicKey = null;
        try {
            publicKey = IOUtils.toString(resource.getInputStream(), Charset.forName("UTF-8"));
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
        converter.setVerifierKey(publicKey);

        return converter;
    }

    /**
     * Default token services using a JWT token store.
     * @return defaultTokenServices
     */
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(this.tokenStore());
        return defaultTokenServices;
    }

    /**
     * Implementation to access the payload user information from the
     * authentication context.
     * @param tokenStore
     * @return securityContextUserAcessor
     */
    @Bean
    @Autowired
    public SecurityContextUserAcessor getCurrentUserAcessor(TokenStore tokenStore) {
        return new SecurityContextUserAcessor(tokenStore);
    }

    /**
     * Bean to perform operations with JWT.
     * @return tokenOperations
     */
    @Bean
    @Autowired
    public TokenOperations getTokenOperations() {
        return new JwtTokenOperations();
    }
}
