package com.local.service.provider.api.gateway.service;

import com.local.service.provider.api.gateway.entity.Role;
import com.local.service.provider.api.gateway.entity.User;

public interface UserService {
	User createUser(String email, String username, String passwordHash);

	void assignRoleToUser(User user, Role.RoleName roleName);

	void grantPermissionToRole(Role.RoleName roleName, String permissionName);
}
