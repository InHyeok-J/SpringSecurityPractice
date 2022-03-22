package com.security.jwt.config.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class JwtTokenDto {

  private String accessToken;

  private String email;
}
