
package com.security.jwt.exception;

public class NotFountUserException extends RuntimeException {

  private static final String message = "없는 유저입니다.";

  public NotFountUserException() {
    super(message);
  }
}
