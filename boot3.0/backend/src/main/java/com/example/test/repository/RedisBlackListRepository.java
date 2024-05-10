package com.example.test.repository;

import com.example.test.domain.redis.BlackList;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RedisBlackListRepository extends CrudRepository<BlackList, String> {
}
