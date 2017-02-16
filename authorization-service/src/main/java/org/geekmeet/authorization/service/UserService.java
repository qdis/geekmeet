package org.geekmeet.authorization.service;

import org.geekmeet.authorization.domain.User;
import org.geekmeet.authorization.exception.UserAlreadyExistsException;
import org.geekmeet.authorization.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.Principal;

public class UserService implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public void registerUser(User user) {

		User existingUser = userRepository.findOne(user.getUsername());
		if (existingUser == null) {
			if(user.getPassword()!=null) {
				user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
			}
			userRepository.save(user);
		} else {
			throw new UserAlreadyExistsException();
		}
	}

	public void deleteUser(Principal self) {
		userRepository.delete(self.getName());
	}

	public User findUserForSocialLogin(String username) {
		return userRepository.findOne(username);
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		User user = userRepository.findOne(username);
		if (user == null) {
			throw new UsernameNotFoundException(username);
		}

		return user;
	}

	public void updateUser(User systemUser) {
		userRepository.save(systemUser);
	}
}
