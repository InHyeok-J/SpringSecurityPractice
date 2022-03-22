package com.security.jwt.config.security.authentication;

import java.util.Collection;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class PostAuthentication extends UsernamePasswordAuthenticationToken {

  private PostAuthentication(Object principal, Object credentials,
      Collection<? extends GrantedAuthority> authorities) {
    super(principal, credentials, authorities);
  }

  public PostAuthentication(UserDetails userDetails) {
    super(userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
  }

}
