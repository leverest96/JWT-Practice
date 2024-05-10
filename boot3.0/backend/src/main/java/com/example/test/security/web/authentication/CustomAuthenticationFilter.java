package com.example.test.security.web.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFilter;

import java.io.IOException;

public class CustomAuthenticationFilter extends AuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(final AuthenticationManager authenticationManager,
                                      final AuthenticationConverter authenticationConverter) {
        super(authenticationManager, authenticationConverter);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {
        try {
            final CustomAuthenticationConverter authenticationConverter = new CustomAuthenticationConverter();

            final Authentication jwtAuthenticationToken = authenticationConverter.convert(request);

            final Authentication authentication = authenticationManager.authenticate(jwtAuthenticationToken);

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (final AuthenticationException authenticationException) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
