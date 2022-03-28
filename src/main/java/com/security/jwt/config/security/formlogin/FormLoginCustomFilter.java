package com.security.jwt.config.security.formlogin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.config.security.dto.LoginDto;
import java.io.IOException;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class FormLoginCustomFilter extends AbstractAuthenticationProcessingFilter {

  private AuthenticationSuccessHandler authenticationSuccessHandler;
  private AuthenticationFailureHandler authenticationFailureHandler;

  protected FormLoginCustomFilter(String defaultFilterProcessesUrl) {
    super(defaultFilterProcessesUrl);
  }

  public FormLoginCustomFilter(AntPathRequestMatcher defaultUrl,
      AuthenticationSuccessHandler authenticationSuccessHandler,
      AuthenticationFailureHandler authenticationFailureHandler) {
    super(defaultUrl);
    this.authenticationSuccessHandler = authenticationSuccessHandler;
    this.authenticationFailureHandler = authenticationFailureHandler;
  }

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
  protected void successfulAuthentication(
      HttpServletRequest req,
      HttpServletResponse res,
      FilterChain chain,
      Authentication authResult
  ) throws IOException, ServletException {
    this
        .authenticationSuccessHandler
        .onAuthenticationSuccess(req, res, authResult);
  }

  // 4.
  @Override
  protected void unsuccessfulAuthentication(
      HttpServletRequest req,
      HttpServletResponse res,
      AuthenticationException failed
  ) throws IOException, ServletException {
    this
        .authenticationFailureHandler
        .onAuthenticationFailure(req, res, failed);
  }

}
