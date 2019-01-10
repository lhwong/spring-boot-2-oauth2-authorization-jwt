package com.kristijangeorgiev.auth.configuration;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.CompositeFilter;



/**
 * 
 * @author Kristijan Georgiev
 *
 */
//@EnableWebSecurity
@Configuration
@EnableOAuth2Client
@Order(200)
@Component
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
	private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfiguration.class);


	@Autowired
	private UserDetailsService userDetailsService;
	
	private OAuth2ClientContext oAuth2ClientContext;
    private OAuthClientConfigurationProperties github;
    private OAuthClientConfigurationProperties oauthVanilla;
    
    //@Autowired
    //private CustomAuthenticationSuccessHandler successHandler;

    
    public WebSecurityConfiguration(OAuth2ClientContext oAuth2ClientContext,
            @Qualifier("github") OAuthClientConfigurationProperties github,
            @Qualifier("oauth2-vanilla") OAuthClientConfigurationProperties oauthVanilla
            ) {

		this.oAuth2ClientContext = oAuth2ClientContext;
		this.github = github;
		this.oauthVanilla =  oauthVanilla;
		
		this.logTheConfig("Github", github);
        this.logTheConfig("OAuth2 Vanilla", oauthVanilla);
		
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	

	@Override
	public void configure(HttpSecurity http) throws Exception {
		/*http.csrf().disable().exceptionHandling()
				.authenticationEntryPoint(
						(request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
				.and().authorizeRequests().antMatchers("/**").authenticated().and().httpBasic();
		 */	
		/*http
			.formLogin().permitAll()
		.and()
			.requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
		.and()
			.authorizeRequests().anyRequest().authenticated();
		 */		
		http
        // From the root '/' down...
        .antMatcher("/**")
        // requests are authorised...
        .authorizeRequests()
            // ...to these url's...
            .antMatchers("/", "/login**", "/webjars/**")
            // ...without security being applied...
            .permitAll()
            // ...any other requests...
            .anyRequest()
            // ...the user must be authenticated.
            .authenticated()
        .and()
            .exceptionHandling()
            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        .and()
            .logout()
            .logoutSuccessUrl("/")
            .permitAll()
        .and()
            .formLogin()
            .loginPage("/login")
		.and()
        	// ...and enable CSRF support using a Cookies strategy...
        	.csrf()
        	.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		.and()
        // ...and ensure our filters are constructed and used before other filters.
        .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);


	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}
	
	
	/**
     * This helper method builds a {@link CompositeFilter} list containing
     * {@link Filter} objects for our two OAuth providers (Google and GitHub).
     * @return
     */
    private Filter ssoFilter() {
        String githubPath = "/login/github";
        String oauth2VanillaPath = "/login/oauth2-vanilla";
        
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();

        LOGGER.info("Creating the Servlet Filter for Github on {}...", githubPath);
        filters.add(ssoFilter(github, githubPath));
        LOGGER.info("Creating the Servlet Filter for oauth2-vanilla on {}...", oauth2VanillaPath);
        filters.add(ssoFilter(oauthVanilla, oauth2VanillaPath));
        
        
        filter.setFilters(filters);
        return filter;
    }

    /**
     * This helper method is used to build {@link OAuth2ClientAuthenticationProcessingFilter} objects
     * based on the configuration properties and the filter path given.
     * @param client {@link OAuthClientConfigurationProperties}
     * @param path
     * @return
     */
    private Filter ssoFilter(OAuthClientConfigurationProperties client, String path) {
        LOGGER.info("Builing the OAuth2ClientAuthenticationProcessingFilter for the path: {}", path);
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oAuth2ClientContext);
        filter.setRestTemplate(template);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId());
        tokenServices.setRestTemplate(template);
        filter.setTokenServices(tokenServices);
        //filter.setAuthenticationSuccessHandler(successHandler);
        
        return filter;
    }
	
	private void logTheConfig(String name, OAuthClientConfigurationProperties client){
        LOGGER.debug("Using the OAuth configuration for {} as follows...", name);
        LOGGER.debug("User info uri: {}", client.getResource().getUserInfoUri());
        LOGGER.debug("Access token uri: {}", client.getClient().getAccessTokenUri());
        LOGGER.debug("Authentication scheme: {}", client.getClient().getAuthenticationScheme());
        LOGGER.debug("Client authentication scheme: {}", client.getClient().getClientAuthenticationScheme());
        LOGGER.debug("Grant type: {}", client.getClient().getGrantType());
    }
	
	/*@Component
    public static class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	    @Override
	    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
	                                        Authentication authentication) throws IOException, ServletException {
	    	LOGGER.debug("$$$$$$$$$$$$$$$$$$$$");
	    	response.sendRedirect("http://localhost:8080/");
	    }
    }*/

}