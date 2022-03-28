package com.security.jwt.config.security.formlogin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.config.security.dto.JwtTokenDto;
import com.security.jwt.util.jwt.JwtProvider;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class FormLoginSuccessHandler implements AuthenticationSuccessHandler {

  private final JwtProvider jwtProvider;
  private final ObjectMapper objectMapper;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    PostAuthentication token = (PostAuthentication) authentication;

    String jwt = jwtProvider.createToken(token);
    JwtTokenDto dto = new JwtTokenDto(jwt, (String) token.getPrincipal());
    sendResponse(response, dto);
  }

  private void sendResponse(HttpServletResponse response, JwtTokenDto dto) throws IOException {
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpStatus.OK.value());
    response.getWriter().write(objectMapper.writeValueAsString(dto));
  }
}
