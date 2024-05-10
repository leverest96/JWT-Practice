package com.example.test.service;

import com.example.test.domain.Member;
import com.example.test.domain.enums.GenderType;
import com.example.test.domain.enums.LoginType;
import com.example.test.domain.enums.MemberRole;
import com.example.test.domain.redis.BlackList;
import com.example.test.domain.redis.RefreshToken;
import com.example.test.dto.MemberInfoResponseDto;
import com.example.test.dto.MemberLoginRequestDto;
import com.example.test.dto.MemberLoginResponseDto;
import com.example.test.dto.MemberRegisterRequestDto;
import com.example.test.exception.MemberException;
import com.example.test.exception.status.MemberStatus;
import com.example.test.repository.MemberRepository;
import com.example.test.repository.RedisBlackListRepository;
import com.example.test.repository.RedisRefreshTokenRepository;
import com.example.test.utility.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final RedisRefreshTokenRepository redisRefreshTokenRepository;
    private final RedisBlackListRepository redisBlackListRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtProvider accessTokenProvider;
    private final JwtProvider refreshTokenProvider;

    public boolean checkEmailExistence(final String email) {
        return memberRepository.findByEmailAndLoginType(email, LoginType.NONE).isPresent();
    }

    @Transactional
    public void register(final MemberRegisterRequestDto requestDto) {
        if (checkEmailExistence(requestDto.getEmail())) {
            throw new MemberException(MemberStatus.EXISTING_EMAIL);
        }

        final Member member = Member.builder()
                .loginId(UUID.randomUUID().toString())
                .nickname(requestDto.getNickname())
                .email(requestDto.getEmail())
                .password(passwordEncoder.encode(requestDto.getPassword()))
                .profile("https://play-lh.googleusercontent.com/38AGKCqmbjZ9OuWx4YjssAz3Y0DTWbiM5HB0ove1pNBq_o9mtWfGszjZNxZdwt_vgHo")
                .roleType(requestDto.isAdmin() ? MemberRole.ADMIN : MemberRole.MEMBER)
                .loginType(LoginType.NONE)
                .genderType(GenderType.BLANK)
                .build();

        memberRepository.save(member);
    }

    @Transactional
    public MemberLoginResponseDto login(final MemberLoginRequestDto requestDto) {
        final Optional<Member> result = memberRepository.findByEmailAndLoginType(requestDto.getEmail(), LoginType.NONE);

        if (result.isEmpty()) {
            throw new MemberException(MemberStatus.NOT_EXISTING_EMAIL);
        }

        final Member member = result.get();

        if (!passwordEncoder.matches(requestDto.getPassword(), member.getPassword())) {
            throw new MemberException(MemberStatus.INCORRECT_PASSWORD);
        }

        if (!member.getLoginType().equals(LoginType.NONE)) {
            throw new MemberException(MemberStatus.INCORRECT_LOGIN_TYPE);
        }

        final Long memberId = member.getId();
        final String loginId = member.getLoginId();

        final String accessToken = accessTokenProvider.createAccessToken(memberId, loginId);
        final String refreshToken = refreshTokenProvider.createRefreshToken(memberId);

        if (redisBlackListRepository.findById(refreshToken).isPresent()) {
            throw new MemberException(MemberStatus.BLACK_LIST_REFRESH_TOKEN);
        }

        redisRefreshTokenRepository.save(
                new RefreshToken(RefreshToken.REFRESH_TOKEN_KEY + memberId, refreshToken)
        );

        member.updateRefreshToken(refreshToken);

        return MemberLoginResponseDto.builder()
                .accessToken(accessToken)
                .build();
    }

    public MemberInfoResponseDto member(final String loginId) {
        final Member member = memberRepository.findByLoginId(loginId).orElseThrow(
                () -> new MemberException(MemberStatus.NOT_EXISTING_MEMBER)
        );

        return MemberInfoResponseDto.builder()
                .email(member.getEmail())
                .nickname(member.getNickname())
                .build();
    }

    @Transactional
    public void removeToken(final long memberId) {
        final Optional<RefreshToken> refreshToken = redisRefreshTokenRepository.findById(
                RefreshToken.REFRESH_TOKEN_KEY + memberId
        );

        if (refreshToken.isPresent()) {
            final String exRefreshToken = refreshToken.map(RefreshToken::getRefreshToken).orElse(null);

            redisBlackListRepository.save(new BlackList(exRefreshToken, BlackList.BLACK_LIST_VALUE));

            redisRefreshTokenRepository.deleteById(RefreshToken.REFRESH_TOKEN_KEY + memberId);

            final Member member = memberRepository.findById(memberId).orElseThrow(
                    () -> new MemberException(MemberStatus.NOT_EXISTING_MEMBER)
            );

            member.updateRefreshToken(null);
        } else {
            throw new IllegalArgumentException("로그인하지 않은 유저입니다.");
        }
    }
}