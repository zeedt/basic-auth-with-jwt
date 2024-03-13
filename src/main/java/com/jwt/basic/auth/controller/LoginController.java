package com.jwt.basic.auth.controller;


import com.jwt.basic.auth.dto.request.LoginRequestDto;
import com.jwt.basic.auth.dto.response.TokenResponseDto;
import com.jwt.basic.auth.service.LoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/login")
@RestController
public class LoginController {

    final LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping
    public TokenResponseDto login(@Valid @RequestBody LoginRequestDto loginRequestDto, HttpServletRequest httpServletRequest) {
        return loginService.login(loginRequestDto, httpServletRequest);
    }

}
