package com.security.jwt.config.security.jwtauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.exception.dto.ErrorResponse;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {


  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    log.info("인증 실패" + authException.getMessage());

    sendResponse(response, authException.getMessage());
  }

  private void sendResponse(HttpServletResponse response, String message) throws IOException {
    ObjectMapper objectMapper = new ObjectMapper();
    ErrorResponse errorResponse = new ErrorResponse(401, message);

    response.setCharacterEncoding("UTF-8");
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
  }
}
