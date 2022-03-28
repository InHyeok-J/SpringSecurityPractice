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
    throw new NoSuchElementException("인증 정보가 정확하지 않습니다.");
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

# JWT 인증

.. 추후 추가 예정 (코드 구현 완료)

### 참고

- https://github.com/alalstjr/Java-spring-boot-security-jwt
- 시큐리티 문서
- 구글링

### 그 외

- FormLogin 같은 경위 위의 출처에 있는 깃헙 README에 자세하게 설명 돼 있습니다.
