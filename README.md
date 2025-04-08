# jwt

# 🔐 Spring Boot + Spring Security + JWT 인증 프로젝트
```markdown
이 프로젝트는 Spring Security와 JWT(Json Web Token)를 활용하여 인증/인가 처리를 구현한 예제입니다.  
RESTful API를 사용하는 백엔드에서 세션 없이 토큰 기반 인증을 처리하는 구조로 되어있습니다.
```

## 📂 프로젝트 구조
```
src
└── main
    ├── java
    │   └── com.cos.jwt
    │       ├── JwtApplication.java
    │       ├── config
    │       │   ├── auth
    │       │   │   ├── PrincipalDetails.java
    │       │   │   └── PrincipalDetailService.java
    │       │   └── jwt
    │       │       ├── JwtAuthenticationFilter.java
    │       │       ├── JwtAuthorizationFilter.java
    │       │       ├── JwtProperties.java
    │       ├── controller
    │       │   └── RestApiController.java
    │       ├── filter
    │       │   ├── MyFilter1.java
    │       │   ├── MyFilter2.java
    │       │   └── MyFilter3.java
    │       ├── model
    │       │   └── User.java
    │       └── repository
    │           └── UserRepository.java
    └── resources
        ├── static
        ├── templates
        └── application.yml
```


## 🧠 핵심 개념 요약

| 구성요소 | 역할 | 핵심 기능 |
```yaml
| `JwtAuthenticationFilter` | 로그인 시 동작 | 사용자 인증 → JWT 생성 및 반환 |
| `JwtAuthorizationFilter` | 모든 요청 시 동작 | JWT 검증 → 사용자 인증 정보 SecurityContext에 저장 |
| `SecurityConfig` | 전체 시큐리티 설정 | 필터 등록, URL 접근 권한 설정 |
| `CorsConfig` | 프론트엔드 연동 지원 | CORS 허용 설정 |
| `FilterConfig` | 커스텀 필터 예제 | 필터 순서 및 등록 방식 설명 |
| `PrincipalDetails` | UserDetails 구현체 | 인증된 사용자 정보 보관 |
| `PrincipalDetailService` | UserDetailsService 구현체 | DB에서 사용자 조회 |
```


## 🔑 JWT 인증 흐름

### 🔹 로그인 요청 (`/login`)
1. `JwtAuthenticationFilter`가 요청을 가로챔
2. JSON 형식의 username/password를 파싱
3. DB 유저 정보 검증 → 인증 성공 시 JWT 발급
4. JWT는 응답 헤더(`Authorization`)에 포함되어 클라이언트에 전달됨

### 🔹 인증된 요청 (e.g. `/api/v1/user/**`)
1. `JwtAuthorizationFilter`가 요청을 가로챔
2. Authorization 헤더에서 JWT 추출 → 검증
3. 검증 성공 시 `Authentication` 객체 생성 및 SecurityContext에 저장
4. Spring Security는 해당 요청을 인증된 사용자로 처리



## 📌 주요 설정 정리

### 🔐 SecurityConfig

```java
http
    .csrf(csrf -> csrf.disable())
    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .formLogin(form -> form.disable())
    .httpBasic(basic -> basic.disable())
    .addFilter(corsFilter)
    .addFilter(new JwtAuthenticationFilter(authenticationManager))
    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository))
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
        .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
        .anyRequest().permitAll()
    );
```
🌐 CorsConfig
```java
config.setAllowCredentials(true);
config.addAllowedOrigin("*");
config.addAllowedHeader("*");
config.addAllowedMethod("*");
```
✅ CORS는 프론트에서 Authorization 헤더나 쿠키 등을 보낼 수 있도록 설정

🧪 필터 순서 확인용 예제 (MyFilter1, MyFilter2, MyFilter3)
FilterConfig.java에 등록된 필터는 순서대로 실행되며,
Spring Security의 필터보다 먼저 또는 이후로 동작하게 설정할 수 있습니다.
```java
@Bean
FilterRegistrationBean<MyFilter1> filter1() {
    FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
    bean.addUrlPatterns("/*");
    bean.setOrder(1);
    return bean;
}
```

🧬 기술 스택
Java 17

Spring Boot 3.4.4

Spring Security

JWT

Lombok

MySQL 

✅ 테스트 계정 예시
```json
{
  "username": "testuser",
  "password": "1234"
}
```
📮 API 인증 방식
모든 인증된 요청에는 다음과 같은 헤더를 포함해야 합니다:
```html
Authorization: Bearer <your_jwt_token>
```
✨ 기타 참고
UserDetails, UserDetailsService는 Spring Security에서 인증 정보를 보관하고 검증하기 위한 핵심 인터페이스입니다.

JWT는 기본적으로 서버에 상태를 저장하지 않기 때문에 완전한 Stateless 인증 구조를 구현할 수 있습니다.

필터 체인을 이해하면 인증/인가뿐만 아니라 로깅, 트래픽 제어 등 다양한 커스터마이징이 가능해집니다.

📎 실행 방법
application.yml 설정

DB 및 User 엔티티 설정

Postman 또는 프론트에서 /login으로 JWT 발급 요청

이후 모든 요청에 JWT 포함하여 호출

💬 Author
👨‍💻 이 프로젝트는 JWT 기반 인증 학습 및 실습용으로 제작되었습니다.
필요한 경우 자유롭게 수정 및 확장하여 사용 가능합니다.
