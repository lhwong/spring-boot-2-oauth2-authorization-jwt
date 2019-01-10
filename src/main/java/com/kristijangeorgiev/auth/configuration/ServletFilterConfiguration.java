package com.kristijangeorgiev.auth.configuration;


import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;


/**
 * Supports the redirects from our app to our OAuth providers.
 *
 * This is handled in Spring OAuth2 with a servlet Filter, and the
 * filter is already available in the application context because
 * we used @EnableOAuth2Client.
 *
 * All that is needed is to wire the filter up so that it gets called
 * in the right order in our Spring Boot application. To do that we
 * need a FilterRegistrationBean:
 */

@Configuration
public class ServletFilterConfiguration {

    @Bean
    public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();
        registration.setFilter(filter);
        registration.setOrder(-100); // Set our filter to have a higher priority.
        return registration;
    }
}
