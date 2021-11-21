package com.jmg.oauth.config;


import com.jmg.oauth.jwt.JwtAuthenticationFilter;
import com.jmg.oauth.jwt.JwtAuthorizationFilter;
import com.jmg.oauth.repository.UserRepository;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

import lombok.RequiredArgsConstructor;

@Configuration // IoC 할 수 있게
@EnableWebSecurity // security 활성화
@RequiredArgsConstructor // DI
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    private final CorsFilter corsFilter;
    private final UserRepository userRepository;
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        // session을 사용하지 않겠다 - jwt 서버만들땐 필수
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .addFilter(corsFilter) // @CrossOrigin(인증x), 인증이 필요한 요청은 이 곳에서 cors 필터 해제해야함
        .formLogin().disable() // form login 사용 안함
        .httpBasic().disable() // 기본적인 http 로그인 방식 사용 안함
        .addFilter(new JwtAuthenticationFilter(authenticationManager())) // WebSecurityConfigurerAdapter 안에 authenticationManager 존재
        .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository))
        .authorizeRequests()
        .antMatchers("/api/v1/user/**")
        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/manager/**")
        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/admin/**")
        .access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll();
    }
}
