package com.cos.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.jwt.model.User;


// CRUD 함수를 JpaRepository가 들고 있음
// @Repository라는 어노테이션이 없어도 ioC가 됨. 이유는 JpaRepository를 상속 했기 때문
public interface UserRepository extends JpaRepository<User, Long> {

	// finBy 규칙 -> Username 문법
	// select * from user where username = ?
	public User findByUsername(String username); // Jpa Qurey methods 검색
	
}
