package com.local.service.provider.api.gateway.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.local.service.provider.api.gateway.entity.Permission;
import com.local.service.provider.api.gateway.entity.User;
import com.local.service.provider.api.gateway.entity.UserPermission;

@Repository
public interface UserPermissionRepository extends JpaRepository<UserPermission, Integer> {

	List<UserPermission> findByUser(User user);

	boolean existsByUserAndPermission(User user, Permission permission);

}
