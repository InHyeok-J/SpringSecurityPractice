package com.security.jwt.exception;

import com.security.jwt.exception.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ControllerExceptionHandler {

  @ExceptionHandler(value = {
      DuplicateEmailException.class,
      NotFountUserException.class
  })
  public ResponseEntity<ErrorResponse> exception(RuntimeException e) {
    ErrorResponse response = new ErrorResponse(HttpStatus.BAD_REQUEST.value(), e.getMessage());
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .body(response);
  }
}
