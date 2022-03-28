package com.security.jwt.config.security.formlogin;

import com.security.jwt.config.security.service.CustomUserDetailService;
import java.util.NoSuchElementException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
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
    return PreAuthentication.class.isAssignableFrom(authentication);
    //authencation 객체와 Provider 연결
  }

  private boolean passwordCheck(String password, String dbPassword) {
    return passwordEncoder.matches(password, dbPassword);
  }
}
