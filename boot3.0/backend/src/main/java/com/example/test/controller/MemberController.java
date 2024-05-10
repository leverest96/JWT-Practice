package com.example.test.controller;

import com.example.test.dto.MemberInfoResponseDto;
import com.example.test.dto.MemberLoginRequestDto;
import com.example.test.dto.MemberLoginResponseDto;
import com.example.test.dto.MemberRegisterRequestDto;
import com.example.test.properties.jwt.AccessTokenProperties;
import com.example.test.security.web.userdetails.MemberDetails;
import com.example.test.service.MemberService;
import com.example.test.utility.CookieUtility;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/member")
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @RequestMapping(value = "/email/{email}", method = RequestMethod.HEAD)
    public ResponseEntity<Void> checkEmailExistence(@PathVariable final String email) {
        return (memberService.checkEmailExistence(email)) ?
                (ResponseEntity.ok().build()) :
                (ResponseEntity.notFound().build());
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody final MemberRegisterRequestDto requestDto) {
        memberService.register(requestDto);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<MemberLoginResponseDto> login(final HttpServletResponse response,
                                                        @RequestBody final MemberLoginRequestDto requestDto) {
        final MemberLoginResponseDto responseDto = memberService.login(requestDto);

        CookieUtility.addCookie(response, AccessTokenProperties.COOKIE_NAME, responseDto.getAccessToken());

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("")
    public ResponseEntity<MemberInfoResponseDto> member(@AuthenticationPrincipal final MemberDetails memberDetails) {
        final MemberInfoResponseDto responseDto = memberService.member(memberDetails.getLoginId());

        return ResponseEntity.ok().body(responseDto);
    }

    @PostMapping("/removeToken")
    public ResponseEntity<Void> removeToken(@AuthenticationPrincipal final MemberDetails memberDetails) {
        memberService.removeToken(memberDetails.getMemberId());

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(final HttpServletResponse response) {
        CookieUtility.deleteCookie(response, AccessTokenProperties.COOKIE_NAME);

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}