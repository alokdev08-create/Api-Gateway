package com.local.service.provider.api.gateway.model;

import java.io.Serializable;
import java.util.List;

import com.local.service.provider.api.gateway.entity.Role;

import lombok.Data;

@Data
public class UserResponse implements Serializable {
	private static final long serialVersionUID = 1L;
	private Integer userId;
	private String email;
	private String username;
	private String profilePicture;
	private List<Role.RoleName> roles;
	private List<String> permissions;
}