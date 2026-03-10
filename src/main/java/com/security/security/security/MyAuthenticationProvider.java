package com.security.security.security;

import com.security.security.repositories.CustomerRepository;
import lombok.AllArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.stream.Collectors;

@Component
@AllArgsConstructor
public class MyAuthenticationProvider implements AuthenticationProvider {

    private CustomerRepository customerRepository;
    private PasswordEncoder passwordEncoder;

    @Override
    public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final var userName = authentication.getName();
        final var password = authentication.getCredentials().toString();
        System.out.println("MyAuthenticationProvider.authenticate - username recibido: " + userName);
        System.out.println("MyAuthenticationProvider.authenticate - password recibido: " + password);
        final var customerBd = customerRepository.findByEmail(userName);
        final var customer = customerBd.orElseThrow(() -> {
            System.out.println("MyAuthenticationProvider.authenticate - no se encontró usuario en BD");
            return new BadCredentialsException("Invalid credentials");
        });
        final var encodedPassword = customer.getPassword();
        System.out.println("MyAuthenticationProvider.authenticate - password en BD: " + encodedPassword);

        if (passwordEncoder.matches(password, encodedPassword)) {
            System.out.println("MyAuthenticationProvider.authenticate - passwords coinciden");
            final var roles = customer.getRoles();
            final var authorities = roles.stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName()))
                    .collect(Collectors.toList());
            return new UsernamePasswordAuthenticationToken(userName, password, authorities);
        } else {
            System.out.println("MyAuthenticationProvider.authenticate - passwords NO coinciden");
            throw new BadCredentialsException("Invalid credentials");
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
