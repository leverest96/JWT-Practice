package com.example.test.exception.handler;

import com.example.test.domain.Member;
import com.example.test.domain.redis.BlackList;
import com.example.test.domain.redis.RefreshToken;
import com.example.test.exception.ExceptionResponse;
import com.example.test.exception.MemberException;
import com.example.test.exception.status.MemberStatus;
import com.example.test.properties.jwt.AccessTokenProperties;
import com.example.test.repository.MemberRepository;
import com.example.test.repository.RedisBlackListRepository;
import com.example.test.repository.RedisRefreshTokenRepository;
import com.example.test.utility.CookieUtility;
import com.example.test.utility.JwtProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.WebUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class AuthenticationExceptionHandler implements AuthenticationEntryPoint {
    private final MemberRepository memberRepository;
    private final RedisRefreshTokenRepository redisRefreshTokenRepository;
    private final RedisBlackListRepository redisBlackListRepository;

    private final JwtProvider accessTokenProvider;
    private final JwtProvider refreshTokenProvider;

    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public void commence(final HttpServletRequest request,
                         final HttpServletResponse response,
                         final AuthenticationException authException) throws IOException {
        final Cookie accessTokenCookie = WebUtils.getCookie(request, AccessTokenProperties.COOKIE_NAME);
        final String providedAccessToken = (accessTokenCookie == null) ? null : accessTokenCookie.getValue();

        long memberId = 0;
        Member member = null;

        try {
            if (!checkAccessTokenExpiration(providedAccessToken)) {
                memberId = accessTokenProvider.getLongClaimFromExpirationToken(providedAccessToken, AccessTokenProperties.AccessTokenClaim.MEMBER_ID.getClaim());
                final String loginId = accessTokenProvider.getStringClaimFromExpirationToken(providedAccessToken, AccessTokenProperties.AccessTokenClaim.LOGIN_ID.getClaim());

                member = memberRepository.findById(memberId).orElseThrow(
                        () -> new MemberException(MemberStatus.NOT_EXISTING_MEMBER)
                );

                final Optional<RefreshToken> redisRefreshToken = redisRefreshTokenRepository.findById(RefreshToken.REFRESH_TOKEN_KEY + memberId);
                final String exRefreshToken = redisRefreshToken.map(RefreshToken::getRefreshToken).orElse((null));

                if (!verifyRefreshToken(exRefreshToken)) {
                    final long exRefreshTokenMemberId = refreshTokenProvider.getLongClaimFromExpirationToken(exRefreshToken,
                            AccessTokenProperties.AccessTokenClaim.MEMBER_ID.getClaim());

                    if (exRefreshTokenMemberId == memberId) {
                        final String newRefreshToken = refreshTokenProvider.createRefreshToken(exRefreshTokenMemberId);

                        if (redisBlackListRepository.findById(newRefreshToken).isPresent()) {
                            throw new MemberException(MemberStatus.BLACK_LIST_REFRESH_TOKEN);
                        }

                        redisBlackListRepository.save(new BlackList(exRefreshToken, BlackList.BLACK_LIST_VALUE));

                        redisRefreshTokenRepository.deleteById(RefreshToken.REFRESH_TOKEN_KEY + memberId);
                        redisRefreshTokenRepository.save(new RefreshToken(RefreshToken.REFRESH_TOKEN_KEY + memberId, newRefreshToken));

                        member.updateRefreshToken(newRefreshToken);
                    } else {
                        redisBlackListRepository.save(new BlackList(exRefreshToken, BlackList.BLACK_LIST_VALUE));

                        redisRefreshTokenRepository.deleteById(RefreshToken.REFRESH_TOKEN_KEY + memberId);

                        member.updateRefreshToken(null);

                        throw new Exception();
                    }
                }

                final String accessToken = accessTokenProvider.createAccessToken(memberId, loginId);

                CookieUtility.addCookie(response, AccessTokenProperties.COOKIE_NAME, accessToken);

                response.sendRedirect(request.getRequestURI());
            }
        } catch (final Exception ex) {
            final String[] uriTokens = request.getRequestURI().substring(1).split("/");

            log.warn("Authentication exception occurrence: {}", authException.getMessage());

            CookieUtility.deleteCookie(response, AccessTokenProperties.COOKIE_NAME);

            redisRefreshTokenRepository.findById(RefreshToken.REFRESH_TOKEN_KEY + memberId).ifPresent(redisRefreshTokenRepository::delete);

            if (member != null) {
                member.updateRefreshToken(null);
            }

            if (uriTokens.length > 0 && uriTokens[0].equals("api")) {
                final String responseBody = objectMapper.writeValueAsString(
                        new ExceptionResponse(List.of(authException.getMessage()))
                );

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.getWriter().write(responseBody);
            } else if (providedAccessToken == null) {
                response.sendRedirect("http://localhost:5173/");
            } else {
                response.sendRedirect(request.getRequestURI());
            }
        }
    }

    private boolean checkAccessTokenExpiration(final String accessToken) {
        if (accessToken == null) {
            throw new IllegalArgumentException();
        }

        try {
            return accessTokenProvider.validateToken(accessToken);
        } catch (final Exception ex) {
            throw new BadCredentialsException(ex.getMessage());
        }
    }

    private boolean verifyRefreshToken(final String refreshToken) {
        if (refreshToken == null) {
            throw new IllegalArgumentException();
        }

        try {
            return refreshTokenProvider.validateToken(refreshToken);
        } catch (final Exception ex) {
            throw new BadCredentialsException(ex.getMessage());
        }
    }
}