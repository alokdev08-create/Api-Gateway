package com.local.service.provider.api.gateway.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.local.service.provider.api.gateway.entity.User;
import com.local.service.provider.api.gateway.entity.UserRole;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Integer> {
	 List<UserRole> findByUser(User user);
}
