package com.jwt.basic.auth.service.impl;

import com.jwt.basic.auth.dto.request.LoginRequestDto;
import com.jwt.basic.auth.dto.response.TokenResponseDto;
import com.jwt.basic.auth.rsa.RSAUtil;
import com.jwt.basic.auth.service.LoginService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class LoginServiceImpl implements LoginService {

  final PasswordEncoder passwordEncoder;

  final RSAUtil rsaUtil;

  private final ObjectMapper objectMapper = new ObjectMapper();

  public LoginServiceImpl(PasswordEncoder passwordEncoder, RSAUtil rsaUtil) {
    this.passwordEncoder = passwordEncoder;
    this.rsaUtil = rsaUtil;
    objectMapper.registerModule(new JavaTimeModule());
  }

  @Override
  public TokenResponseDto login(LoginRequestDto loginRequestDto, HttpServletRequest httpServletRequest) {
    if (!loginRequestDto.getUsername().equals("ola@email.com")) throw new BadCredentialsException("Invalid credentials");

    if (!"P@ssw0rd".equals(loginRequestDto.getPassword()))
      throw new BadCredentialsException("Invalid credentials");

    var roles = getRoles();
    var issDate = LocalDateTime.now();
    var expiryDate = LocalDateTime.now().plusDays(7);
    String token = rsaUtil.generateToken(loginRequestDto.getUsername(), "user-id", roles, expiryDate, issDate);
    return TokenResponseDto.builder()
        .roles(roles)
        .expiryDate(expiryDate.toString())
        .issueDate(expiryDate.toString())
        .token(token)
        .build();
  }

  private List<String> getRoles() {
    return List.of("ADMIN");
  }
}