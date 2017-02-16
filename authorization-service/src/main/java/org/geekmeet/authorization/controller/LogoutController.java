package org.geekmeet.authorization.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@RestController
public class LogoutController {

	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public ResponseEntity<Void> logoutPage(HttpServletRequest request) {

		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
			SecurityContextHolder.clearContext();
		}

		return new ResponseEntity<>(HttpStatus.OK);
	}

}