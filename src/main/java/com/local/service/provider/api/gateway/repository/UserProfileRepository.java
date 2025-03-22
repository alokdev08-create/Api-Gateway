package com.local.service.provider.api.gateway.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.local.service.provider.api.gateway.entity.UserProfile;

@Repository
public interface UserProfileRepository extends JpaRepository<UserProfile, Integer> {
	Optional<UserProfile> findByUserUserId(Integer userId);

    boolean existsByUserUserId(Integer userId);
}
