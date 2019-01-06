package com.kristijangeorgiev.auth.configuration;

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;


/**
 * This class is created by the {@link GoogleClientConfigurationProperties} and {@link GithubClientConfigurationProperties} beans
 * and models the structure in the application properties with both "client" and "resource"
 * branches in the property tree. Hence the use of @{@link NestedConfigurationProperty}.
 */
public class OAuthClientConfigurationProperties {

    @NestedConfigurationProperty
    private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();

    public AuthorizationCodeResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }
}
