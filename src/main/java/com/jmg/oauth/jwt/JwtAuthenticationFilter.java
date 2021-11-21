package com.jmg.oauth.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmg.oauth.auth.PrincipalDetails;
import com.jmg.oauth.model.User;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password를 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작
// formLogin 안쓰기로 했기에 동작하지 않지만 security config에서 add filter로 등록하면 됨
// 이때 AuthenticationManager를 꼭 받아와야함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
   private final AuthenticationManager authenticationManager; // 생성자로 받아옴
   
   // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
   @Override
   public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
           throws AuthenticationException {
       // 1. username, password 받아서
       try {
           // json 데이터로 들어온다고 가정
           ObjectMapper om = new ObjectMapper(); // json 데이터를 객체로 파싱
           User user = om.readValue(request.getInputStream(), User.class);
            // token 생성
           UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
           // token을 보내 로그인 시도 (principalDetailsService가 호출 loadUserByUsername() 함수 실행)
           // 정상적으로 실행되면 로그인 성공 (db에 있는 username과 password가 일치)
           Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 인증이 되서 authentication 객체가 session 영역에 저장
            // 리턴 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것
            // 굳이 jwt 토큰을 사용하면서 세션을 만들 이유가 없지만 권한 처리때문에 session 사용
            return authentication;
       } catch (Exception e) {
           return null;
       }
       // 2. 정상인지 로그인 시도 -> AuthenticationManager로 로그인 시도를 하면 
       // 3. principalDetailsService가 호출 loadUserByUsername() 함수 실행
       // 4. PrincipalDetails를 세션에 담고 -> 담지 않으면 security가 권한 관리를 못함
       // 5. JWT 토큰을 만들어서 응답
       
   }
   // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수 실행
   // 이곳에서 jwt 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
   @Override
   protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
           Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwtToken = JWT.create()
            .withSubject("jwt")
            .withExpiresAt(new Date(System.currentTimeMillis()+(60000)*10))
            .withClaim("id", principalDetails.getUser().getId())
            .withClaim("username", principalDetails.getUser().getUsername())
            .sign(Algorithm.HMAC512("cos"));
        response.addHeader("Authorization", "Bearer "+jwtToken);
   }
}
