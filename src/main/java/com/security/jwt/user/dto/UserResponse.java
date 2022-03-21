package com.security.jwt.user.dto;

import com.security.jwt.user.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserResponse {

  private Long id;

  private String email;

  private String username;

  public static UserResponse to(User user) {
    return new UserResponse(user.getId(), user.getEmail(), user.getUsername());
  }
}
