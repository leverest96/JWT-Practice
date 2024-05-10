package com.example.test.utility;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.http.ResponseCookie;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CookieUtility {
    public static ResponseCookie createCookie(final String name, final String value) {
        return ResponseCookie.from(name, value)
                .path("/")
//                .sameSite("Lax")
                .httpOnly(true)
                .secure(false)
                .build();
    }

    public static ResponseCookie createCookie(final String name, final String value, final int maxAge) {
        return ResponseCookie.from(name, "")
                .path("/")
//                .sameSite("Lax")
                .httpOnly(true)
                .secure(false)
                .maxAge(maxAge)
                .build();
    }

    public static ResponseCookie createExpirationCookie(final String name) {
        return ResponseCookie.from(name, "")
                .path("/")
                .httpOnly(true)
                .secure(false)
                .maxAge(0)
                .build();
    }

    public static void addCookie(final HttpServletResponse response,
                                 final ResponseCookie cookie) {
        response.addHeader("Set-Cookie", cookie.toString());
    }

    public static void addCookie(final HttpServletResponse response,
                                 final String name,
                                 final String value) {
        addCookie(response, createCookie(name, value));
    }

    public static void deleteCookie(final HttpServletResponse response,
                                    final String name) {
        addCookie(response, createExpirationCookie(name));
    }
}