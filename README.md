# SpringSecurityPractice

- Jwt 외에 세션까지 해볼 예정

## 스프링 시큐리티 란?

> Spring Security is a powerful and highly customizable authentication and access-control framework. It is the de-facto standard for securing Spring-based applications.

*위는 문서 설명글입니다.

- 스프링 시큐리티는 Spring 기반의 애플리케이션에서 인증 및 인가 같은 보안 기능을 쉽게 지원해주는 프레임워크

### 어떻게 동작하나?

- Spring Security는 Filter에서 처럼 동작하게 된다.
- Filter는 서블릿 컨테이너의 스펙인데, Bean에 등록된 Security를 어떻게 필터에서 사용하나
- DelegatingFilterProxy 라는 친구가 서블릿 필터에서 요청을 가져와서 **FilterChainProxy** 에게 요청 처리를 위임하게 되고, 이
  FilterChainProxy에는 여러개의 **Spring Security Filter**(springSecurityFilterChain라는 이름으로 된) 이 있어 스프링 빈에
  등록된 Filter들이 동작하면서 보안 처리를 할 수 있게 된다.

## 시큐리티 인증 동작 방식

- 스프링 시큐리티의 기본 동작 방식인 formLogin() 에 대해 알아보면
- SecurityContextPersistenceFilter 와 csrfFilter 를 통과하고 formLogin을 처리하는
  UsernamePasswordAuthenticationFilter에게 오게 된다.
- 이 필터는 자신이 처리해야 하는 Login URL과 맞으면 동작한다.
  <img src="https://user-images.githubusercontent.com/28949213/160400935-94ec214c-5dec-48a1-bb91-13ee8e2b7ccd.png"/>

1. UsernamePasswordAuthenticationFilter 가 수행되면 이 필터는 사용자의 요청Request로부터 username과 password (둘다 기본값)
   인증 정보가 포함된 Authentication 객체 인 UsernamePasswordAuthenticationToken을 생성합니다.
2. 이 객체는 AuthenticationManager에게 전달되며, 인증을 요청합니다.
3. AuthenticationManager은 필터로부터 인증 객체를 받고, 내부적으로 AuthenticationProvider이라는 객체들을 갖고 있는데 이 객체 중 하나를
   선택해서 인증 처리를 위임하게 되고 AuthenticationProvider 가 실제 인증 처리를 하게 됩니다.
4. AuthenticationProvider 중 UsernamePasswordAuthenticationToken을 인증 처리할 수 있는
   DaoAuthenticationProvider를 선택해서 인증 처리를 하고 이 Provider는 token안에 있는 username을 이용해 현재 user 정보를 받아옵니다
5. UserDetailsService에서 loadUserByUsername 메소드를 호출해서 유저 정보를 받아오고 패스워드 일치 등의 검사를 해서 검증 성공후 유저 정보와 권한
   정보가 담긴 Authentication 객체를 반환합니다.
6. AuthenticationManager은 받은 Authentication 객체를 다시 Filter에게 반환하며 이 정보를 SecurityContext와 세션에 저장하게 된다
7. 이후 SuccessHandler가 동작하게 되며 적절한 쿠키 값과 응답값이 리턴되게 된다.


- 아래 코드는 UsernamePasswordAuthenticationFilter 중 일부

```java
@Override
public Authentication attemptAuthentication(HttpServletRequest request,HttpServletResponse response)
    throws AuthenticationException{
    if(this.postOnly&&!request.getMethod().equals("POST")){
    throw new AuthenticationServiceException("Authentication method not supported: "+request.getMethod());
    }
    String username=obtainUsername(request);
    username=(username!=null)?username:"";
    username=username.trim();
    String password=obtainPassword(request);
    password=(password!=null)?password:"";
    UsernamePasswordAuthenticationToken authRequest=new UsernamePasswordAuthenticationToken(username,password);
    // Allow subclasses to set the "details" property
    setDetails(request,authRequest);
    return this.getAuthenticationManager().authenticate(authRequest);
    }
```

- 입력한 값을 통해 UsernamePasswordAuthenticationToken 을 생성하고 AuthenticationManger 에게 전달한다.

## 인증 저장소 - SecurityContextHolder, SecurityContext

### SecurityContext

- Authentication 객체가 저장되는 보관소.
- ThreadLocal에 저장되어 아무 곳에서나 참조가 가능하도록 설계
    - 쓰레드마다 고유하게 할당된 저장소. 쓰레드에 안전함
- 인증이 완료되면 Session을 사용한다면 HttpSession에 저장되어 어플리케이션 전반에 걸쳐 전역적인 참조가 가능하다.

### SecurityContextHolder

- SecurityContext를 감싸는 객체
- SecurityContext의 저장 방식 선택 가능
- MODE_THREADLOCAL : 스레드 당 SecurityContext 객체 할당, default
- MODE_INHERITABLETHREADLOCAL : 메인 스레드와 자식 스레드에 대해 동일한 SecurityContext 유지
- MODE_GLOBAL : 응용 프로그램에서 단 하나의 SecurityContext를 저장

## 인증 관리자 AuthenticationManager

- AuthenticationManager 에게 Authentication 객체가 들어오면 적절한 Provider 를 찾아서 인증 처리를 위임한다
- 부모 ProviderManager 를 설정해서 AuthenticationProvider 를 계속 탐색 가능.
- 시큐리티가 초기화 되면서 2개의 ProviderManager 가 생성됨
    - 익명 사용자용 ProviderManager
    - FormLogin 용 ProviderManager

## 인증 처리자 AuthenticationProvider

- 실제 인증이 처리되는 곳
- `authenticate` 메소드에서 인증 처리
- `supports` 에서 어떤 객체를 처리해야 하는지 결정함.

# Form Login 구현

## Filter

- /config/security/formlogin/FormLoginCustomFilter.java

```java
public class FormLoginCustomFilter extends AbstractAuthenticationProcessingFilter {

  //생성자 생략

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    String body = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));

    LoginDto loginRequest = new ObjectMapper().readValue(body,
        LoginDto.class
    );
    PreAuthentication token = new PreAuthentication(loginRequest);

    return super.getAuthenticationManager().authenticate(token);
  }

  @Override
  protected void successfulAuthentication(...) throws IOException, ServletException {

  }

  @Override
  protected void unsuccessfulAuthentication(...) throws IOException, ServletException {

  }
}
```

- AbstractAuthenticationProcessingFilter 을 상속받아서 구현
- `attemptAuthentication` 에서 먼저 filter 수행
- 인증 전 Authentication 객체를 생성해서 AuthenticationManager 에게 전달
- 인증이 완료되면(AuthenticationManager에게 인증 객체를 잘 받게 되면) successfulAuthentication 수행
- 실패되면 unsuccessfulAuthentication 수행

```java
public class FormLoginProvider implements AuthenticationProvider {

  private final CustomUserDetailService userDetailService;
  private final PasswordEncoder passwordEncoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    PreAuthentication token = (PreAuthentication) authentication;
    String email = token.getEmail();
    String password = token.getPassword();

    //유저가 있는지 검사 후 UserDetail 리턴
    UserDetails user = userDetailService.loadUserByUsername(email);

    if (passwordCheck(password, user.getPassword())) {
      return new PostAuthentication(user);
    }

    //인증 실패시
    throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
  }

  @Override
  public boolean supports(Class<?> authentication) {
    //authencation 객체와 Provider 연결
    return PreAuthentication.class.isAssignableFrom(authentication);
  }

  private boolean passwordCheck(String password, String dbPassword) {
    return passwordEncoder.matches(password, dbPassword);
  }
}
```

- provider 에서 실제 인증이 수행됨
- supports 로 어떤 인증 객체를 처리해야 하는지 정의해줌
- `CustomUserDetailService`에서 `loadUserByUsername`유저 정보를 받아 온 후 password가 일치하는지 확인
- 이후 인증이 완료되면 인증 정보와 권한 정보가 담긴 Authentication 객체를 생성해서 리턴함.

```java
public class CustomUserDetailService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    return userRepository.findByEmail(email)
        .map(user -> createUser(email, user))
        .orElseThrow(() -> new UsernameNotFoundException(email + " 을 찾을 수 없습니다."));
  }

  private org.springframework.security.core.userdetails.User createUser(String email,
      User userEntity) {
    Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
    grantedAuthorities.add(new SimpleGrantedAuthority("USER")); // DB에 아무 값도 없어서 임의로 둠.
    return new org.springframework.security.core.userdetails.User(email, userEntity.getPassword(),
        grantedAuthorities);
  }
}
```

- 실제 DB랑 연결해서 User정보를 가져온 후 UserDetail 리턴

- 이후 인증이 완료되면 직접 구현한 `FormLoginSuccessHandler` 에서 JWT를 발급해서 응답해줌.

지금까지 설정한 Filter는 UsernamePasswordAuthenticationFilter 앞에 설정.

### FormLogin Exception Handling

- FormLogin의 Filter는 AuthenticationException 을 캐치하고 있다.
- 내부적으로 호출하는 에러에 기본적으로 제공해주는 다음과 같은 AuthenticationException 종류의 예외를 사용해야 했습니다.
- BadCredentialsException
- UsernameNotFoundException
- 위 2개 사용
- 그 외에 종류들은
- AccountExpiredException
- CredentialsExpiredException
- DisabledException
- LockedException

# JWT 인증

- 위에서 구현한건 로그인 요청에 대한 필터이고 JWT가 포함된 request 요청이 왔을때 핸들링 해줘야 하는 필터를 구현해야 합니다.

## Config

```java
public class JwtSecurityConfig extends
    SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

  private JwtProvider jwtProvider;

  public JwtSecurityConfig(JwtProvider jwtProvider) {
    this.jwtProvider = jwtProvider;
  }

  @Override
  public void configure(HttpSecurity http) {
    //에외 api 추가
    List<AntPathRequestMatcher> skip = new ArrayList<>();
    skip.add(new AntPathRequestMatcher("/", HttpMethod.GET.name()));
    skip.add(new AntPathRequestMatcher("/api/login", HttpMethod.POST.name()));
    skip.add(new AntPathRequestMatcher("/api/user", HttpMethod.POST.name()));

    JwtFilter customFilter = new JwtFilter(jwtProvider, skip);
    JwtExceptionFilter jwtExceptionFilter = new JwtExceptionFilter();
    http.addFilterAfter(customFilter, UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(jwtExceptionFilter, JwtFilter.class);
  }
}
```

## Filter

- OncePerRequestFilter을 상속받아서 구현한 JwtFilter를 구현합니다.
- filter의 역할은 아주 간단한데, 헤더에 Jwt가 있는지 검사하고, 유효한 jwt인지 확인한 다음 SecurityContextHolder에 인증 객체를 저장하는 역할입니다.

```java
public class JwtFilter extends OncePerRequestFilter {

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String HEADER_PREFIX = "Bearer ";
  private final OrRequestMatcher orRequestMatcher;

  public JwtFilter(JwtProvider jwtProvider, List<AntPathRequestMatcher> skipPath) {
    this.jwtProvider = jwtProvider;
    this.orRequestMatcher = new OrRequestMatcher(new ArrayList<>(skipPath));
  }


  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    if (orRequestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    //헤더 검사
    String jwtToken = extractToken(request);

    if (jwtProvider.validateToken(jwtToken)) {
      //유효한 Jwt토큰이면 컨텍스트에 저장
      UserDetails userInfo = jwtProvider.getUserDetail(jwtToken);
      Authentication authentication = new PostAuthentication(userInfo);
      SecurityContextHolder.getContext().setAuthentication(authentication);
      log.info("Security Contexrt에 " + authentication.getPrincipal() + " 인증 정보 저장 완료");

    } else {
      log.info("유효한 JWT 토큰이 아닙니다.");
    }
    //다음 필터 실행
    filterChain.doFilter(request, response);
  }

  private String extractToken(HttpServletRequest request) {
    String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(HEADER_PREFIX)) {
      return bearerToken.substring(HEADER_PREFIX.length());
    } else {
      throw new JwtException("Header에 token이 없습니다.");
    }
  }
}
```

- SecurityContextHolder에 인증 객체를 저장하는 이유는 전역적으로 참고하기 위해서 인데
- JwtFilter 외의 다음 Filter들이 SecurityContextHolder에 저장된 인증 객체를 보고 처리를 하고 이후에 Controller에서도 사용하기 위해서
  입니다.
- 이 JwtFilter는 UsernamePasswordAuthenticationFilter 기준으로 뒤에다 위치시켰고, 위의 FormLogin은 앞에 위치시켰습니다.
- orRequestMatcher는 AntPathRequestMatcher들 중에서 하나라도 맞으면 true를 리턴하며, 이걸 통해서 검사를 하면 안되는 api를 셋팅합니다.

## JWT Filter Exception Handling

- 요청에 상태에 따라서 다양한 응답을 처리하고 싶은 상황인데 기존에 ExceptionTranslationFilter(맨 마지막 위치) 가 처리하는
  AuthenticationEntryPoint와 AccessDeniedHandler로 처리하려고 했으나
- 로직 상 인증 객체가 없기 때문에 익명 사용자용 AuthenticationException이 발생하게 되고 message가 default값이 설정됩니다.
- 그래서 JwtFilter 앞 단에 JwtExceptionFilter를 둬서 Jwt를 검증할떄 발생하는 에러를 캐치해서 응답시켜주는 방식으로 구현했습니다.

```java

@Component
public class JwtExceptionFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    try {
      filterChain.doFilter(request, response);
    } catch (JwtException e) {
      e.printStackTrace();
      sendResponse(response, e);
    }
  }

  private void sendResponse(HttpServletResponse response, JwtException jwtException)
      throws IOException {
    ...응답 로직
  }
}
```

- 사용자의 요청이 들어오면 JwtExceptionFilter가 먼저 호출하게 되고 이 필터는 FilterChain.doFilte로 JwtFilter를 호출합니다.
- 이 JwtFilter에서 발생하는 에러를 핸들링해서 각 상황에 맞는 응답을 처리합니다.

# 인가 제어

- 스프링 시큐리티에서 인가 처리는 크게 FilterSecurityInterceptor, AccessDecisionManager, AccessDecisionVoter 3개가
  관여한다.
- 필터들의 목록을 보면 아래와 같은데   
  <img src="https://user-images.githubusercontent.com/28949213/161551915-9a3caf57-845c-4bd7-bf82-38c5c283eec8.png"/>
- ExceptionTranslationFilter가 위에서 JwtFilter의 Exception을 처리한 것 처럼 try catch로 감싸서
  FilterSecurityInterceptor에서 처리하는 예외를 받아서 핸들링을 하며 인가 처리는 FilterSecurityInterceptor 에서 처리한다.

- 인가 처리 결정은 AccessDecisionManager가 처리를 하는데, 처리를 하기 위해서는 인증 정보(SpringSecurityContext에 저장된
  Authentication 객체)와 요청 정보(AntMatcher), 권한 정보(hasRole or hasAuthority)가 필요하다
- FilterSecurityIntercepter는 먼저 인증 정보가 있는지 체크 후 없으면 예외를, 있으면 권한 정보를 체크하며 권한 정보가 없는 자원이면 응답, 권한 정보가
  필요한 자원이면 AccessDecisionManager에게 위임한다.

### AccessDecisionManager

- 위에서 말한 것처럼 권한 여부를 판단한다.
- 여러 개의 Voter 들을 가질 수 있으며 Voter들로부터 접근 허용, 거부, 보류에 해당하는 각각의 값을 리턴 받고 판단 및 결정한다.
- 접근 결정의 세가지 유형
    - AffirmativeBased:
        - 여러 개의 Voter클래스 중 하나라도 접근 허가로 결론을 내면 허가로 판단
    - ConsensusBased :
        - 다수표(승인 및 거부)에 의해 최종 결정을 판단
    - UnanimousBased
        - 모든 Voter가 만장일치로 접근을 승인해야 하며 그렇지 않은 경우 접근을 거부함.

### 표현식

- hasRole(String) -> 사용자가 주어진 **역할**이 있다면 허용, 검사시에 앞에 ROLE_ 라는 prefix를 붙여서 검사.ex) hasRole("USER")
- hasAuthority(String) -> 사용자가 주어진 **권한**이 있다면 접근을 허용 , ex) hasAuthority("ROLE_USER")
- hasAnyRole(String) -> 여러 역할 중 하나만 일치해도 허용
- hasAnyAuthority(String) -> 여러 권한 중 하나만 일치해도 허용
- access(String) -> 주어진 SpEL 표현식의 평가 결과가 true이면 접근을 허용 ex)access("hasRole('ADMIN') or hasRole('
  SYS')")

### 참고

- https://github.com/alalstjr/Java-spring-boot-security-jwt
- 시큐리티 문서
- https://velog.io/@ewan/Spring-security-success-failure-handler FormLogin Exception 참고
- https://velog.io/@hellonayeon/spring-boot-jwt-expire-exception  JWT Exception 참고.

### 그 외

- FormLogin 같은 경위 위의 출처에 있는 깃헙 README에 자세하게 설명 돼 있습니다.
