package com.jmg.oauth.auth;

import com.jmg.oauth.model.User;
import com.jmg.oauth.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
// http://localhost:8080/login 요청이 올때 동작 => 그러나 formLogin을 안쓰기로 했기에 동작 안함
// 그래서 filter에 등록
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{
    
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
    
}
