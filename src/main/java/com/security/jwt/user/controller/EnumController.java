package com.security.jwt.user.controller;

import com.security.jwt.constant.EnumMapper;
import com.security.jwt.constant.EnumModel;
import com.security.jwt.constant.EnumValue;
import com.security.jwt.constant.UserRole;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/enum")
@RequiredArgsConstructor
public class EnumController {

  private final EnumMapper enumMapper;

  @GetMapping("")
  public Map<String, Object> getEnum() {
    Map<String, Object> enums = new LinkedHashMap<>();
    Class userRole = UserRole.class;
    enums.put("userRole", userRole.getEnumConstants());

    return enums;
  }

  @GetMapping("/mapper")
  public Map<String, List<EnumValue>> getEnumValue() {
    return enumMapper.getAll();
  }

}
