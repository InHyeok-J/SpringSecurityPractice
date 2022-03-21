package com.security.jwt.user.controller;

import com.security.jwt.user.dto.UserCreateRequest;
import com.security.jwt.user.dto.UserResponse;
import com.security.jwt.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

  private final UserService userService;

  @PostMapping("")
  public ResponseEntity<UserResponse> signUP(@RequestBody UserCreateRequest request) {
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(UserResponse.to(userService.signUp(request)));
  }
}
