package com.local.service.provider.api.gateway.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.local.service.provider.api.gateway.entity.Permission;
import com.local.service.provider.api.gateway.entity.Role;
import com.local.service.provider.api.gateway.entity.RolePermission;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermission, Integer> {
	boolean existsByRoleAndPermission(Role role, Permission permission);
    List<RolePermission> findByRole(Role role);
}
