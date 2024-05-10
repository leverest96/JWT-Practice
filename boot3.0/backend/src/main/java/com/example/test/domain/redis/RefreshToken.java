package com.example.test.domain.redis;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;

@AllArgsConstructor
@Getter
@RedisHash(value = "refresh_token", timeToLive = 60*60*24*7)
public class RefreshToken {
    public static final String REFRESH_TOKEN_KEY = "refresh_token_";

    @Id
    private String id;

    private String RefreshToken;
}
