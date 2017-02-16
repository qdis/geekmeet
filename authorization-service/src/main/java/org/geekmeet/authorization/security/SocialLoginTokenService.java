package org.geekmeet.authorization.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.geekmeet.authorization.domain.User;
import org.geekmeet.authorization.service.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.Collections;
import java.util.Map;

public class SocialLoginTokenService implements ResourceServerTokenServices {

	protected final Log logger = LogFactory.getLog(this.getClass());
	private final String userInfoEndpointUrl;
	private final String clientId;
	private final UserService userService;
	private OAuth2RestOperations restTemplate;
	private String tokenType = "Bearer";

	public SocialLoginTokenService(String userInfoEndpointUrl, String clientId, UserService userService) {
		this.userInfoEndpointUrl = userInfoEndpointUrl;
		this.clientId = clientId;
		this.userService = userService;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	public void setRestTemplate(OAuth2RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	public OAuth2Authentication loadAuthentication(String accessToken)
			throws AuthenticationException, InvalidTokenException {
		Map map = this.getMap(this.userInfoEndpointUrl, accessToken);
		if (map.containsKey("error")) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("userinfo returned error: " + map.get("error"));
			}

			throw new InvalidTokenException(accessToken);
		} else {
			return this.extractAuthentication(map);
		}
	}

	private OAuth2Authentication extractAuthentication(Map<String, Object> map) {
		OAuth2Request request = new OAuth2Request(null, this.clientId, null, true,
			null, null, null, null, null);
		User systemUser;
		String email = map.get("email").toString();
		systemUser = userService.findUserForSocialLogin(email);
		if (systemUser != null) {
			if (!systemUser.isFacebookLogin()) {
				systemUser.setFacebookLogin(true);
				userService.updateUser(systemUser);
			}
		} else {

			systemUser = new User();
			systemUser.setUsername(email);
			systemUser.setFirstName(map.get("first_name") != null ?
					map.get("first_name").toString() :
					map.get("given_name") != null ? map.get("given_name").toString() : null);
			systemUser.setLastName(map.get("last_name") != null ?
					map.get("last_name").toString() :
					map.get("family_name") != null ? map.get("family_name").toString() : null);
			systemUser.setFacebookLogin(true);
			systemUser.addAuthority("ROLE_USER");

			userService.registerUser(systemUser);
		}

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(systemUser, "N/A",
				systemUser.getAuthorities());
		//token.setDetails(map);
		return new OAuth2Authentication(request, token);
	}

	public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}

	private Map<String, Object> getMap(String path, String accessToken) {
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("Getting user info from: " + path);
		}

		try {
			Object ex = this.restTemplate;
			if (ex == null) {
				BaseOAuth2ProtectedResourceDetails existingToken = new BaseOAuth2ProtectedResourceDetails();
				existingToken.setClientId(this.clientId);
				ex = new OAuth2RestTemplate(existingToken);
			}

			OAuth2AccessToken existingToken1 = ((OAuth2RestOperations) ex).getOAuth2ClientContext().getAccessToken();
			if (existingToken1 == null || !accessToken.equals(existingToken1.getValue())) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(accessToken);
				token.setTokenType(this.tokenType);
				((OAuth2RestOperations) ex).getOAuth2ClientContext().setAccessToken(token);
			}

			return (Map) ((OAuth2RestOperations) ex).getForEntity(path, Map.class, new Object[0]).getBody();
		} catch (Exception var6) {
			var6.printStackTrace();
			this.logger.warn("Could not fetch user details: " + var6.getClass() + ", " + var6.getMessage());
			return Collections.singletonMap("error", "Could not fetch user details");
		}
	}
}