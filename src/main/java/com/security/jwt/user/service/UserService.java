package com.security.jwt.user.service;

import com.security.jwt.exception.DuplicateEmailException;
import com.security.jwt.exception.NotFountUserException;
import com.security.jwt.user.dto.UserCreateRequest;
import com.security.jwt.user.entity.User;
import com.security.jwt.user.repository.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public User signUp(UserCreateRequest dto) {
    checkDuplicateEmail(dto.getEmail());

    User newUSer = dto.toEntity();
    newUSer.setPassword(passwordEncoder.encode(dto.getPassword()));

    return userRepository.save(newUSer);
  }

  public User findOne(String email) {
    Optional<User> findUser = userRepository.findByEmail(email);
    if (findUser.isPresent()) {
      return findUser.get();
    }
    throw new NotFountUserException();
  }

  private void checkDuplicateEmail(String email) {
    Optional<User> existUser = userRepository.findByEmail(email);
    if (existUser.isPresent()) {
      throw new DuplicateEmailException();
    }
  }
}
