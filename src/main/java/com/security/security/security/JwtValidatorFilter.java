package com.security.security.security;

import com.security.security.services.JwtService;
import com.security.security.services.JwtUserDetailService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Component
@AllArgsConstructor
@Slf4j
public class JwtValidatorFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final JwtUserDetailService jwtUserDetailService;
    private static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final var requestTokenHeader = request.getHeader(AUTHORIZATION_HEADER);
        String username = null;
        String jwtToken = null;

        if (Objects.nonNull(requestTokenHeader)
                && requestTokenHeader.toLowerCase().startsWith(TOKEN_PREFIX.toLowerCase())) {

            // Corta justo después de "Bearer " (ignorando mayúsculas/minúsculas)
            jwtToken = requestTokenHeader.substring(TOKEN_PREFIX.length());

            // Limpia cualquier espacio o carácter de espacio en blanco en TODO el token
            if (jwtToken != null) {
                jwtToken = jwtToken.replaceAll("\\s", "");
            }

            try {
                username = jwtService.getUsernameFromToken(jwtToken);
            } catch (ExpiredJwtException e) {
                log.warn("JWT token is expired: {}", e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT expired");
                return;
            } catch (SignatureException e) {
                log.error("JWT signature invalid: {}", e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT signature");
                return;
            } catch (DecodingException e) {
                log.error("JWT token cannot be decoded: {}", e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Malformed JWT token");
                return;
            } catch (IllegalArgumentException e) {
                log.error("Invalid JWT token: {}", e.getMessage());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
                return;
            } catch (Exception e) {
                // Cualquier otra excepción relacionada con el parsing del JWT
                log.error("Unexpected error while parsing JWT token", e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
                return;
            }
        }

        if (Objects.nonNull(username) && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
            final var userDetails = jwtUserDetailService.loadUserByUsername(username);

            if (this.jwtService.validateToken(jwtToken, userDetails)) {
                var usernameAndPassAuthToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                usernameAndPassAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernameAndPassAuthToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
