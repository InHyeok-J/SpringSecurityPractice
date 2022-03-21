package com.security.jwt.user.dto;

import com.security.jwt.user.entity.User;
import lombok.Getter;

@Getter
public class UserCreateRequest {

  private String email;

  private String username;

  private String password;

  public User toEntity() {
    return User.builder()
        .email(this.email)
        .username(this.username)
        .password(this.password)
        .build();
  }
}
