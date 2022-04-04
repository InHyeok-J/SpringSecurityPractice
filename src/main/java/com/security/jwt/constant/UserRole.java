package com.security.jwt.constant;

import lombok.Getter;

@Getter
public enum UserRole implements EnumModel {

  ADMIN("ROLE_ADMIN"),
  USER("ROLE_USER");

  private final String role;

  UserRole(String role) {
    this.role = role;
  }

  @Override
  public String getKey() {
    return name();
  }

  @Override
  public String getValue() {
    return role;
  }
}
