package com.security.security.dto;

import lombok.Data;

@Data
public class JwtRequestDto {

    private String username;
    private String password;

}
