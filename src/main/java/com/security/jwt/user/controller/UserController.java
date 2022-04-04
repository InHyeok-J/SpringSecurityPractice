package com.security.jwt.user.controller;

import com.security.jwt.config.security.LoginUser;
import com.security.jwt.config.security.dto.AuthUser;
import com.security.jwt.user.dto.UserCreateRequest;
import com.security.jwt.user.dto.UserResponse;
import com.security.jwt.user.entity.User;
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
    System.out.println(authentication.getName());
    System.out.println(authentication.getAuthorities());

    User findUser = userService.findOne(authentication.getName());
    return ResponseEntity.status(HttpStatus.OK)
        .body(UserResponse.to(findUser));
  }

  @GetMapping("/info-aop")
  public ResponseEntity<?> userInfoAop(@LoginUser AuthUser user) {
    User findUser = userService.findOne(user.getEmail());
    return ResponseEntity.status(HttpStatus.OK)
        .body(UserResponse.to(findUser));
  }
}
