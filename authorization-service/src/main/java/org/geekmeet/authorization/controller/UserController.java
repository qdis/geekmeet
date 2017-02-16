package org.geekmeet.authorization.controller;

import org.geekmeet.authorization.domain.User;
import org.geekmeet.authorization.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;


@RestController
public class UserController {

	@Autowired
	private UserService userService;

	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<Void> register(@RequestBody User user) {
		userService.registerUser(user);
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@RequestMapping(value = "/me", method = RequestMethod.GET)
	public ResponseEntity<UserDetails> me(Principal principal) {
		if (principal != null) {
			return new ResponseEntity<>(userService.loadUserByUsername(principal.getName()), HttpStatus.OK);
		}
		return new ResponseEntity<>(HttpStatus.NOT_FOUND);
	}

	@RequestMapping(value = "/delete-account", method = RequestMethod.DELETE)
	public ResponseEntity<Void> register(Principal principal) {
		userService.deleteUser(principal);
		return new ResponseEntity<>(HttpStatus.OK);
	}
}
