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
```yml
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

🔸 JwtAuthenticationFilter.java (로그인 처리)
```java
@Override
public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
    ObjectMapper om = new ObjectMapper();
    User user = om.readValue(request.getInputStream(), User.class);

    UsernamePasswordAuthenticationToken authToken =
        new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

    Authentication authentication = authenticationManager.authenticate(authToken);
    return authentication;
}
```
📌 로그인 요청 시 username/password를 검증하고 인증 수행

```java
@Override
protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                        FilterChain chain, Authentication authResult) {
    String jwtToken = JWT.create()
        .withSubject("cos토큰")
        .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
        .withClaim("id", principalDetails.getUser().getId())
        .withClaim("username", principalDetails.getUser().getUsername())
        .sign(Algorithm.HMAC512(JwtProperties.SECRET));

    response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
}

```
📌 인증 성공 시 JWT를 생성하고 응답 헤더에 추가합니다.

🔸 JwtAuthorizationFilter (JWT 검증)
```java
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws IOException, ServletException {

    String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);

    if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
        chain.doFilter(request, response);
        return;
    }

    String jwtToken = jwtHeader.replace(JwtProperties.TOKEN_PREFIX, "");

    String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
            .build()
            .verify(jwtToken)
            .getClaim("username")
            .asString();

    if (username != null) {
        User userEntity = userRepository.findByUsername(username);
        PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                principalDetails, null, principalDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    chain.doFilter(request, response);
}

```
📌 요청 헤더에서 JWT를 추출하고 서명을 검증한 후, 정상적인 경우 Authentication 객체를 생성하여 SecurityContext에 저장합니다. 이 과정을 통해 Spring Security는 해당 요청을 인증된 사용자로 인식합니다.

🔸 SecurityConfig.java (보안 설정)
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
📌 Stateless 인증 구조로 설정 + 필터 등록 + 접근 권한 설정

🔸 CorsConfig (CORS 허용)
```java
config.setAllowCredentials(true);
config.addAllowedOrigin("*");
config.addAllowedHeader("*");
config.addAllowedMethod("*");
```
📌 모든 Origin/CORS 요청 허용 (운영 환경에서는 addAllowedOrigin("http://your-frontend.com") 식으로 제한하는 게 좋습니다.)

🔸 MyFilter3.java (테스트용 필터 예제)
```java
if(req.getMethod().equals("POST")) {
    String headerAuth = req.getHeader("Authorization");

    if(headerAuth.equals("cos")) {
        chain.doFilter(req, res);
    } else {
        res.getWriter().println("인증안됨");
    }
}
```
📌 학습용 테스트 필터. 실서비스에서는 사용하지 않음

🔑 테스트 계정 예시
```json
POST /login
{
  "username": "testuser",
  "password": "1234"
}
```
요청 성공 시, 응답 헤더에 아래와 같은 JWT가 포함됩니다.
```
Authorization: Bearer <your_jwt_token>
```
이후 모든 API 요청 시 이 헤더를 포함해야 인증됩니다.

🚀 실행 방법
1. application.yml에 MySQL DB 설정

2. 프로젝트 실행

3. Postman 또는 프론트엔드에서 /login 요청

4. 응답 헤더의 JWT 토큰 → 이후 요청에 포함

5. API 권한별 접근 필터링 확인

🧬 기술 스택
- Java 17

- Spring Boot 3.4.4

- Spring Security

- JWT (java-jwt 라이브러리)

- Lombok

- MySQL

✨ 기타 참고
UserDetails, UserDetailsService는 Spring Security의 인증 기반 클래스입니다.

JWT 기반 인증은 서버에 인증 상태를 저장하지 않기 때문에 Stateless 구조에 적합합니다.

필터 체인을 이해하면 인증뿐 아니라 로깅, 모니터링, 권한 체크 등의 확장도 가능합니다.

💬 Author
👨‍💻 이 프로젝트는 JWT 기반 인증 학습 및 실습용으로 제작되었습니다.
필요한 경우 자유롭게 수정 및 확장하여 사용 가능합니다.
