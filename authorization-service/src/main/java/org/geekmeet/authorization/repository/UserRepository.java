package org.geekmeet.authorization.repository;

import org.geekmeet.authorization.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {

}
