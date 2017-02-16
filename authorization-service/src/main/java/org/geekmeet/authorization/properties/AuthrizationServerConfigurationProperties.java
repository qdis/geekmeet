package org.geekmeet.authorization.properties;

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Data
@ToString
@ConfigurationProperties("authorization-server")
public class AuthrizationServerConfigurationProperties {

	private JwtProperties jwt = new JwtProperties();

	@Data
	@ToString
	public static class JwtProperties {

		private String privateKeyFile;
		private String publicKeyFile;

	}
}
