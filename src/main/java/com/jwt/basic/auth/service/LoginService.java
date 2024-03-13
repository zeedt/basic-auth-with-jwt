package com.jwt.basic.auth.service;

import com.jwt.basic.auth.dto.request.LoginRequestDto;
import com.jwt.basic.auth.dto.response.TokenResponseDto;
import jakarta.servlet.http.HttpServletRequest;

public interface LoginService {

    TokenResponseDto login(LoginRequestDto loginRequestDto, HttpServletRequest httpServletRequest);
}
