package org.geekmeet.authorization.init;

import org.geekmeet.authorization.domain.User;
import org.geekmeet.authorization.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;

@Service
public class CreateAdminUserService {

	@Autowired
	private UserService userService;

	@PostConstruct
	public void postConstruct() {
		User adminUser = new User("admin", "admin");
		adminUser.addAuthority("ROLE_ADMIN");
		adminUser.addAuthority("ROLE_USER");

		userService.registerUser(adminUser);
	}

}
