package com.security.jwt.user.controller;

import com.security.jwt.config.security.LoginUser;
import com.security.jwt.config.security.dto.AuthUser;
import com.security.jwt.user.dto.UserCreateRequest;
import com.security.jwt.user.dto.UserResponse;
import com.security.jwt.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
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

  @GetMapping("/info")
  public ResponseEntity<?> userInfo() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    System.out.println(authentication.getPrincipal());
    System.out.println(authentication.getCredentials());
    System.out.println(authentication.getDetails());
    System.out.println(authentication.getName());
    System.out.println(authentication.getAuthorities());
    return ResponseEntity.status(HttpStatus.OK)
        .body("SUCCESS!");
  }

  @GetMapping("/info-aop")
  public ResponseEntity<?> userInfoAop(@LoginUser AuthUser user) {
    System.out.println(user.getEmail());
    System.out.println(user.getAuthority());
    return ResponseEntity.status(HttpStatus.OK)
        .body(new UserResponse(1L, user.getEmail(), "닉네임 아직 모름"));
  }
}
