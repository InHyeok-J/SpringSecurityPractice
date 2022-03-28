package com.security.jwt.config.security.jwtauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.exception.dto.ErrorResponse;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

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
    ObjectMapper objectMapper = new ObjectMapper();
    ErrorResponse errorResponse = new ErrorResponse(401, jwtException.getMessage());

    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setCharacterEncoding("UTF-8");
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
  }
}
