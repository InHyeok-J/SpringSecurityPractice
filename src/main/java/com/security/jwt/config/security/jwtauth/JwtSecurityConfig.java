package com.security.jwt.config.security.jwtauth;

import com.security.jwt.util.jwt.JwtProvider;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtSecurityConfig extends
    SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

  private JwtProvider jwtProvider;

  public JwtSecurityConfig(JwtProvider jwtProvider) {
    this.jwtProvider = jwtProvider;
  }

  @Override
  public void configure(HttpSecurity http) {
    JwtFilter customFilter = new JwtFilter(jwtProvider);
    JwtExceptionFilter jwtExceptionFilter = new JwtExceptionFilter();
    http.addFilterAfter(customFilter, UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(jwtExceptionFilter, JwtFilter.class);
  }
}
