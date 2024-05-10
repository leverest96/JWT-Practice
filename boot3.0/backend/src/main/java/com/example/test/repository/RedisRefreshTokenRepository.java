package com.example.test.repository;

import com.example.test.domain.redis.RefreshToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RedisRefreshTokenRepository extends CrudRepository<RefreshToken, String> {
}