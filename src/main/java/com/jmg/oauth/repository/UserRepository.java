package com.jmg.oauth.repository;

import com.jmg.oauth.model.User;

import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Long>{
	User findByUsername(String username);
}
