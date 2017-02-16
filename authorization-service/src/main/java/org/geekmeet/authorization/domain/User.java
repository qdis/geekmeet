package org.geekmeet.authorization.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.common.collect.Lists;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Data
@Entity
@NoArgsConstructor
public class User implements UserDetails {

	@Id
	private String username;

	@Column
	private String password;

	@Column
	private String firstName;

	@Column
	private String lastName;

	@JsonIgnore
	@Column(nullable = false)
	private boolean accountNonLocked = true;

	@JsonIgnore
	@Column(nullable = false)
	private boolean accountNonExpired = true;

	@JsonIgnore
	@Column(nullable = false)
	private boolean credentialsNonExpired = true;

	@JsonIgnore
	@Column(nullable = false)
	private boolean enabled = true;

	@Column(nullable = false)
	private boolean facebookLogin = false;

	@Column(length = 4000)
	private String jwtToken;

	@ElementCollection(fetch = FetchType.EAGER)
	private List<String> authorities;

	public User(String username, String password) {
		this.username = username;
		this.password = password;
		this.authorities = Lists.newArrayList("USER");
	}

	public User(String username, String password, String... authorities) {
		this.username = username;
		this.password = password;
		this.authorities = Lists.newArrayList(authorities);
	}

	public List<GrantedAuthority> getAuthorities() {
		return authorities.stream().map(authority -> new SimpleGrantedAuthority(authority))
				.collect(Collectors.toList());
	}

	public void addAuthority(String authority) {
		if (authorities == null) {
			authorities = new ArrayList<>();
		}
		if (!authorities.contains(authority)) {
			authorities.add(authority);
		}
	}

}
