package com.security.jwt.exception.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public class ErrorResponse {

  private int status;

  private String message;
}
