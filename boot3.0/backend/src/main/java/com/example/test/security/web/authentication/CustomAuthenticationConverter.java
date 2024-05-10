package com.example.test.security.web.authentication;

import com.example.test.properties.jwt.AccessTokenProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.util.WebUtils;

@RequiredArgsConstructor
public class CustomAuthenticationConverter implements AuthenticationConverter {
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    public CustomAuthenticationConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    @Override
    public Authentication convert(final HttpServletRequest request) {
        final Cookie accessTokenCookie = WebUtils.getCookie(request, AccessTokenProperties.COOKIE_NAME);
        final String accessToken = (accessTokenCookie == null) ? null : accessTokenCookie.getValue();

        final PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(null, accessToken);

        result.setDetails(authenticationDetailsSource.buildDetails(request));

        return result;
    }
}
