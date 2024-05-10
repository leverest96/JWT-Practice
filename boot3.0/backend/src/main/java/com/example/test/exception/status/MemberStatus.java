package com.example.test.exception.status;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@RequiredArgsConstructor
@Getter
public enum MemberStatus {
    INCORRECT_PASSWORD(HttpStatus.UNAUTHORIZED, "must be a correct password"),
    NOT_EXISTING_EMAIL(HttpStatus.NOT_FOUND, "must be an existing email"),
    EXISTING_EMAIL(HttpStatus.CONFLICT, "must not be an existing email"),
    NOT_EXISTING_MEMBER(HttpStatus.NOT_FOUND, "must be an existing member"),
    INCORRECT_LOGIN_TYPE(HttpStatus.CONFLICT, "must not be a social login"),
    EXISTING_MEMBER(HttpStatus.CONFLICT, "must not be an existing member"),
    BLACK_LIST_REFRESH_TOKEN(HttpStatus.CONFLICT, "must not exist in the redis black list");

    private final HttpStatus httpStatus;
    private final String message;
}