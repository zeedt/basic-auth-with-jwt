package com.jwt.basic.auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class TokenResponseDto {

    private String token;

    private String expiryDate;

    private String issueDate;

    private List<String> roles;


}