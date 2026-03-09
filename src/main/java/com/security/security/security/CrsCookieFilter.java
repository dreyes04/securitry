package com.security.security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

public class CrsCookieFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        if (Objects.nonNull(csrf.getHeaderName())) {
            response.addHeader(csrf.getHeaderName(), csrf.getToken());
        }

        filterChain.doFilter(request, response);
    }
}
