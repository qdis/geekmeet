package org.geekmeet.authorization.configuration;

import org.apache.commons.io.IOUtils;
import org.geekmeet.authorization.domain.User;
import org.geekmeet.authorization.properties.AuthrizationServerConfigurationProperties;
import org.geekmeet.authorization.security.SocialLoginFilter;
import org.geekmeet.authorization.security.SocialLoginTokenService;
import org.geekmeet.authorization.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class OAuthServerConfiguration extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthrizationServerConfigurationProperties authrizationServerConfigurationProperties;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private DefaultTokenServices defaultTokenServices;

	@Autowired
	private OAuth2ClientContext oauth2ClientContext;

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter()));
		endpoints.tokenStore(tokenStore()).tokenEnhancer(tokenEnhancerChain)
				.authenticationManager(authenticationManager);
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory().withClient("authorization-server").secret("authorization-server-secret")
				.authorizedGrantTypes("authorization_code", "refresh_token", "password").scopes("openid")
				.accessTokenValiditySeconds(0).refreshTokenValiditySeconds(0).autoApprove(true);
	}

	@Bean
	@Primary
	public DefaultTokenServices tokenServices() throws IOException {
		final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter()));
		final DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore());
		tokenServices.setTokenEnhancer(tokenEnhancerChain);
		return tokenServices;
	}

	@Bean
	public TokenStore tokenStore() throws IOException {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}

	@Bean
	@Primary
	public UserService userService() {
		return new UserService();
	}

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() throws IOException {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setSigningKey(IOUtils.toString(
				new FileInputStream(new File(authrizationServerConfigurationProperties.getJwt().getPrivateKeyFile())),
				"UTF-8"));
		converter.setVerifierKey(IOUtils.toString(
				new FileInputStream(new File(authrizationServerConfigurationProperties.getJwt().getPublicKeyFile())),
				"UTF-8"));
		return converter;
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	@Bean
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("google")
	public ClientResources google() {
		return new ClientResources();
	}

	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();
		filters.add(ssoFilter(google(), "/login/google", userService()));
		filters.add(ssoFilter(facebook(), "/login/facebook", userService()));
		filter.setFilters(filters);
		return filter;
	}

	private Filter ssoFilter(ClientResources client, String path, UserService userService) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path) {
			@Override
			protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
					FilterChain chain, Authentication authResult) throws IOException, ServletException {

				OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authResult;

				User user = (User) oAuth2Authentication.getUserAuthentication().getPrincipal();
				OAuth2AccessToken accessToken = defaultTokenServices.createAccessToken(oAuth2Authentication);
				oAuth2Authentication.setDetails(accessToken);
				user.setJwtToken(accessToken.getValue());
				userService.updateUser(user);

				response.sendRedirect("http://geekmeet.app?access_token=" + accessToken.getValue());
				super.successfulAuthentication(request, response, chain, oAuth2Authentication);
			}
		};
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);
		filter.setTokenServices(
				new SocialLoginTokenService(client.getResource().getUserInfoUri(), client.getClient().getClientId(),
						userService()));
		return filter;
	}

	@Bean
	public UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> userDetailsServiceWrapper() {
		UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper = new UserDetailsByNameServiceWrapper<>();
		wrapper.setUserDetailsService(userService());
		return wrapper;
	}

	@Bean
	public PreAuthenticatedAuthenticationProvider preauthAuthProvider() {
		PreAuthenticatedAuthenticationProvider preauthAuthProvider = new PreAuthenticatedAuthenticationProvider();
		preauthAuthProvider.setPreAuthenticatedUserDetailsService(userDetailsServiceWrapper());
		return preauthAuthProvider;
	}

	@Bean
	public SocialLoginFilter jwtTokenFilter() throws Exception {
		SocialLoginFilter filter = new SocialLoginFilter(defaultTokenServices, "Authorization", "access_token");
		filter.setAuthenticationManager(authenticationManager);
		return filter;
	}

	class ClientResources {

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

	@Configuration
	@EnableOAuth2Client
	public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Bean
		public BCryptPasswordEncoder encoder() {
			return new BCryptPasswordEncoder();
		}

		@Bean
		public DaoAuthenticationProvider authenticationProvider() {
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(userService());
			provider.setPasswordEncoder(encoder());
			return provider;
		}

		@Override
		@Autowired
		public void configure(AuthenticationManagerBuilder auth) {
			auth.authenticationProvider(authenticationProvider());
			auth.authenticationProvider(preauthAuthProvider());
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.headers().frameOptions().disable();
			http.addFilterBefore(jwtTokenFilter(), RequestHeaderAuthenticationFilter.class).antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/register/**").permitAll().anyRequest()
				.authenticated().and().exceptionHandling()
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and().logout()
				.logoutSuccessUrl("/").permitAll().and()
				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

		// @formatter:on
		}

		@Configuration
		@EnableResourceServer
		protected class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
			@Override
			public void configure(HttpSecurity http) throws Exception {
				// @formatter:off
			http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
			// @formatter:on
			}
		}

	}

}
