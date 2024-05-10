package com.example.test.domain.redis;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;

@AllArgsConstructor
@Getter
@RedisHash(value = "black_list", timeToLive = 60*60*24*7)
public class BlackList {
    public static final String BLACK_LIST_VALUE = "black_list";

    @Id
    private String id;

    private String value;
}
