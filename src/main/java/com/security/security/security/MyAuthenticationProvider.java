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
        final var customerBd = customerRepository.findByEmail(userName);
        final var customer = customerBd.orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        final var encodedPassword = customer.getPassword();

        if (passwordEncoder.matches(password, encodedPassword)) {
            final var authorities = Collections.singletonList(new SimpleGrantedAuthority(customer.getRol()));
            return new UsernamePasswordAuthenticationToken(userName, password, authorities);
        } else {
            return new UsernamePasswordAuthenticationToken(userName, password, null);
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
