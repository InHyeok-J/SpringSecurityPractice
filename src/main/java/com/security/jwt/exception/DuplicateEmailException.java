package com.security.jwt.exception;

public class DuplicateEmailException extends RuntimeException {

  private static final String message = "이미 존재하는 이메일입니다.";

  public DuplicateEmailException() {
    super(message);
  }
}
