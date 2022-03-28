package com.security.jwt.config.security.dto;

import java.util.Collection;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

@Getter
public class AuthUser {

  private String email;
  private Collection<? extends GrantedAuthority> authority;

  public AuthUser(String email, Collection<? extends GrantedAuthority> authority) {
    this.email = email;
    this.authority = authority;
  }
}
