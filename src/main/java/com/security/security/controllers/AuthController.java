package com.security.security.controllers;

import com.security.security.dto.JwtRequestDto;
import com.security.security.dto.JwtResponse;
import com.security.security.services.JwtService;
import com.security.security.services.JwtUserDetailService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtUserDetailService jwtUserDetailService;
    private final JwtService jwtService;

    @PostMapping("/authenticate")
    public ResponseEntity<?> postToken(@RequestBody JwtRequestDto jwtRequestDto) {
        authenticate(jwtRequestDto);
        final var userDetails = jwtUserDetailService.loadUserByUsername(jwtRequestDto.getUsername());
        final var token = jwtService.generateToken(userDetails);
        return ResponseEntity.ok(new JwtResponse(token));
    }

    private void authenticate(JwtRequestDto jwtRequestDto) {
        this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        jwtRequestDto.getUsername(),
                        jwtRequestDto.getPassword()
                )
        );
    }
}
