package com.security.jwt.config.security.jwtauth;

import com.security.jwt.util.jwt.JwtProvider;
import java.util.ArrayList;
import java.util.List;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class JwtSecurityConfig extends
    SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

  private JwtProvider jwtProvider;

  public JwtSecurityConfig(JwtProvider jwtProvider) {
    this.jwtProvider = jwtProvider;
  }

  @Override
  public void configure(HttpSecurity http) {
    List<AntPathRequestMatcher> skip = new ArrayList<>();
    skip.add(new AntPathRequestMatcher("/", HttpMethod.GET.name()));
    skip.add(new AntPathRequestMatcher("/api/login", HttpMethod.POST.name()));
    skip.add(new AntPathRequestMatcher("/api/user", HttpMethod.POST.name()));
    skip.add(new AntPathRequestMatcher("/api/enum", HttpMethod.GET.name()));
    skip.add(new AntPathRequestMatcher("/api/enum/**", HttpMethod.GET.name()));
    JwtFilter customFilter = new JwtFilter(jwtProvider, skip);
    JwtExceptionFilter jwtExceptionFilter = new JwtExceptionFilter();
    http.addFilterAfter(customFilter, UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(jwtExceptionFilter, JwtFilter.class);
  }
}
