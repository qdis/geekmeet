package org.geekmeet.authorization.security;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;

public class SocialLoginFilter extends RequestHeaderAuthenticationFilter {

	private String requestHeaderName;
	private String requestParamName;
	private DefaultTokenServices defaultTokenServices;

	public SocialLoginFilter(DefaultTokenServices defaultTokenServices, String requestHeaderName,
			String requestParamName) {
		this.requestHeaderName = requestHeaderName;
		this.requestParamName = requestParamName;
		this.defaultTokenServices = defaultTokenServices;
	}

	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		OAuth2Authentication oAuth2Authentication = getPrincipal(request);
		if(oAuth2Authentication != null){
			return oAuth2Authentication.getPrincipal();
		}
		return null;
	}

	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {

		OAuth2Authentication oAuth2Authentication = getPrincipal(request);
		if(oAuth2Authentication != null){
			return oAuth2Authentication.getCredentials();
		}
		return null;
	}

	private OAuth2Authentication getPrincipal(HttpServletRequest request) {
		String token = getToken(request);
		if (token != null) {
			OAuth2Authentication auth = defaultTokenServices.loadAuthentication(token);
			return auth;
		}
		return null;
	}

	private String getToken(HttpServletRequest request) {
		String token = request.getHeader(requestHeaderName);
		if (token == null) {
			token = request.getParameter(requestParamName);
		}
		if (token != null && token.startsWith("Bearer ")) {
			token = token.substring(7);

		}
		return token;
	}

}