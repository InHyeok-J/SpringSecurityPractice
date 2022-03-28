package com.security.jwt.config.security.jwtauth;

import com.security.jwt.config.security.formlogin.PostAuthentication;
import com.security.jwt.util.jwt.JwtProvider;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class JwtFilter extends OncePerRequestFilter {

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String HEADER_PREFIX = "Bearer ";
  private JwtProvider jwtProvider;

  public JwtFilter(JwtProvider jwtProvider) {
    this.jwtProvider = jwtProvider;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
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
