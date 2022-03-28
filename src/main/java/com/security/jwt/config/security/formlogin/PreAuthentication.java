package com.security.jwt.config.security.formlogin;

import com.security.jwt.config.security.dto.LoginDto;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class PreAuthentication extends UsernamePasswordAuthenticationToken {

  private PreAuthentication(Object principal, Object credentials) {
    super(principal, credentials);
  }

  public PreAuthentication(LoginDto dto) {
    this(dto.getEmail(), dto.getPassword());
  }

  public String getEmail(){
    return (String) super.getPrincipal();
  }

  public String getPassword(){
    return (String) super.getCredentials();
  }
}
