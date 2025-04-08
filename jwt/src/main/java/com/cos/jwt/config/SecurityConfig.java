package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final CorsFilter corsFilter;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final UserRepository userRepository;
    
	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	

	
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
    	
        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
    	
//    	http.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class);
    	
        http
	        // CSRF 비활성화 (JWT 기반이라면 필요 없음)
	        .csrf(csrf -> csrf.disable())
	
	        // 세션을 사용하지 않음 (Stateless)
	        .sessionManagement(session -> 
	            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	        )
	        // CorsFilter 설정 
	        .addFilter(corsFilter) // @CrossOrigin(인증 X), 시큐리티 필터에 등록 인증(O)
	        
	        // form 로그인 비활성화
	        .formLogin(form -> form.disable())
	
	        // HTTP Basic 인증 비활성화
	        .httpBasic(basic -> basic.disable())
	
	        .addFilter(new JwtAuthenticationFilter(authenticationManager)) // AuthenticationManager
	        .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository)) // AuthenticationManager
	        
	        // 권한에 따른 요청 접근 제어
	        .authorizeHttpRequests(auth -> auth
	            .requestMatchers("/api/v1/user/**")
	                .hasAnyRole("USER", "MANAGER", "ADMIN")
	            .requestMatchers("/api/v1/manager/**")
	            	.hasAnyRole("MANAGER", "ADMIN")
	        	.requestMatchers("/api/v1/admin/**")
	            	.hasAnyRole("MANAGER", "ADMIN")
	            .anyRequest().permitAll());
	    	
    	return http.build();
    }
	
	
}
