package com.kristijangeorgiev.auth.configuration;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

/**
 * Models the GitHub configuration elements in the application properties
 * and creates a @{@link Bean} containing them.
 */
@Component
public class GithubClientConfigurationProperties {

    @Bean(name = "github")
    @ConfigurationProperties("github")
    public OAuthClientConfigurationProperties github() {
        return new OAuthClientConfigurationProperties();
    }

}
