package com.local.service.provider.api.gateway.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.local.service.provider.api.gateway.entity.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
	 Optional<Role> findByRoleName(Role.RoleName roleName);
}