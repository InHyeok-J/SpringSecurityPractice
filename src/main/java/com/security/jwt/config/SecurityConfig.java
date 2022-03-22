package com.security.jwt.config;

import com.security.jwt.config.security.filter.FormLoginCustomFilter;
import com.security.jwt.config.security.handler.FormLoginFailureHandler;
import com.security.jwt.config.security.handler.FormLoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final FormLoginSuccessHandler formLoginSuccessHandler;
  private final FormLoginFailureHandler formLoginFailureHandler;
//  private final FormLoginProvider provider;

  @Bean
  public AuthenticationManager getAuthenticationManger() throws Exception {
    return super.authenticationManagerBean();
  }

  protected FormLoginCustomFilter formLoginCustomFilter() throws Exception {
    FormLoginCustomFilter filter = new FormLoginCustomFilter(new AntPathRequestMatcher("/api/login",
        HttpMethod.POST.name()),
        formLoginSuccessHandler,
        formLoginFailureHandler
    );
    filter.setAuthenticationManager(super.authenticationManagerBean());
    return filter;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    //필터 등록
    http.addFilterBefore(formLoginCustomFilter(), UsernamePasswordAuthenticationFilter.class);

    //exception Handler

    //토큰 방식을 사용하기 때문에 off 쿠키 안씀
    http
        .csrf()
        .disable();

    //Jwt 방식을 사용할거라서 Session OFF
    http
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    http
        .authorizeRequests()
        .antMatchers("/", "/api/user", "/jwt").permitAll(); // root 조회랑 회원가입운 열어둠
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}
