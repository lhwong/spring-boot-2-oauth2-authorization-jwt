package com.kristijangeorgiev.auth.configuration;

import java.security.KeyPair;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.servlet.view.RedirectView;

import com.kristijangeorgiev.auth.entity.User;

@Configuration
@EnableAuthorizationServer
public class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

	@Value("${check-user-scopes}")
	private Boolean checkUserScopes;

	@Autowired
	private DataSource dataSource;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private ClientDetailsService clientDetailsService;

	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	@Bean
	public OAuth2RequestFactory requestFactory() {
		CustomOauth2RequestFactory requestFactory = new CustomOauth2RequestFactory(clientDetailsService);
		requestFactory.setCheckUserScopes(true);
		return requestFactory;
	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
	}
	
	/*@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		 		
		clients.inMemory().withClient("acme").secret("{noop}password")
				.authorizedGrantTypes("authorization_code", "refresh_token",
						"password")
				.autoApprove(true)
				.authorities("role_user")
				.scopes("openid");
		
	}*/

	@Bean
	public TokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter() {
		return new TokenEndpointAuthenticationFilter(authenticationManager, requestFactory());
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtAccessTokenConverter())
				.authenticationManager(authenticationManager).userDetailsService(userDetailsService);
		if (checkUserScopes)
			endpoints.requestFactory(requestFactory());
		
		endpoints.addInterceptor(new HandlerInterceptorAdapter() {
			@Override
			public void postHandle(HttpServletRequest request,
					HttpServletResponse response, Object handler,
					ModelAndView modelAndView) throws Exception {
				if (modelAndView != null
						&& modelAndView.getView() instanceof RedirectView) {
					RedirectView redirect = (RedirectView) modelAndView.getView();
					String url = redirect.getUrl();
					if (url.contains("code=") || url.contains("error=")) {
						HttpSession session = request.getSession(false);
						if (session != null) {
							session.invalidate();
						}
					}
				}
			}
		});
	}

	/*@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter converter = new CustomTokenEnhancer();
		converter.setKeyPair(
				new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "password".toCharArray()).getKeyPair("jwt"));
		return converter;
	}*/
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		KeyPair keyPair = new KeyStoreKeyFactory(
				new ClassPathResource("keystore.jks"), "foobar".toCharArray())
						.getKeyPair("test");
		converter.setKeyPair(keyPair);
		return converter;
	}

	/*
	 * Add custom user principal information to the JWT token
	 */
	class CustomTokenEnhancer extends JwtAccessTokenConverter {
		@Override
		public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
			System.out.println(authentication.getPrincipal());
			
			User user = (User) authentication.getPrincipal();

			Map<String, Object> info = new LinkedHashMap<String, Object>(accessToken.getAdditionalInformation());

			info.put("email", user.getEmail());

			DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);
			customAccessToken.setAdditionalInformation(info);

			return super.enhance(customAccessToken, authentication);
		}
	}

	class CustomOauth2RequestFactory extends DefaultOAuth2RequestFactory {
		@Autowired
		private TokenStore tokenStore;

		public CustomOauth2RequestFactory(ClientDetailsService clientDetailsService) {
			super(clientDetailsService);
		}

		@Override
		public TokenRequest createTokenRequest(Map<String, String> requestParameters,
				ClientDetails authenticatedClient) {
			if (requestParameters.get("grant_type").equals("refresh_token")) {
				OAuth2Authentication authentication = tokenStore.readAuthenticationForRefreshToken(
						tokenStore.readRefreshToken(requestParameters.get("refresh_token")));
				SecurityContextHolder.getContext()
						.setAuthentication(new UsernamePasswordAuthenticationToken(authentication.getName(), null,
								userDetailsService.loadUserByUsername(authentication.getName()).getAuthorities()));
			}
			return super.createTokenRequest(requestParameters, authenticatedClient);
		}
	}
	


}