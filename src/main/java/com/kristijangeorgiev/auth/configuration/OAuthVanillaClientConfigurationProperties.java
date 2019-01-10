package com.kristijangeorgiev.auth.configuration;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

/**
 * Models the CloudFoundry UAA configuration elements in the application properties
 * and creates a @{@link Bean} containing them.
 */
@Component
public class OAuthVanillaClientConfigurationProperties {

    @Bean(name = "oauth2-vanilla")
    @ConfigurationProperties("oauth2-vanilla")
    public OAuthClientConfigurationProperties uaa() {
        return new OAuthClientConfigurationProperties();
    }

}
