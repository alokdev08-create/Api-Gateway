//package com.local.service.provider.api.gateway.serviceimpl;
//
//import java.util.List;
//import java.util.Map;
//import java.util.stream.Collectors;
//
//import org.springframework.beans.factory.annotation.Autowired;
//
//import com.local.service.provider.api.gateway.entity.Permission;
//import com.local.service.provider.api.gateway.entity.Role;
//import com.local.service.provider.api.gateway.entity.Role.RoleName;
//import com.local.service.provider.api.gateway.model.UserResponse;
//import com.local.service.provider.api.gateway.entity.RolePermission;
//import com.local.service.provider.api.gateway.entity.User;
//import com.local.service.provider.api.gateway.entity.UserRole;
//import com.local.service.provider.api.gateway.repository.PermissionRepository;
//import com.local.service.provider.api.gateway.repository.RolePermissionRepository;
//import com.local.service.provider.api.gateway.repository.RoleRepository;
//import com.local.service.provider.api.gateway.repository.UserRepository;
//import com.local.service.provider.api.gateway.repository.UserRoleRepository;
//import com.local.service.provider.api.gateway.service.UserService;
//
//public class UserServiceImpl implements UserService {
//
//	 @Autowired
//	    private UserRepository userRepository;
//
//	    @Autowired
//	    private RoleRepository roleRepository;
//
//	    @Autowired
//	    private UserRoleRepository userRoleRepository;
//
//	    @Autowired
//	    private PermissionRepository permissionRepository;
//
//	    @Autowired
//	    private RolePermissionRepository rolePermissionRepository;
//
//	    @Override
//	    public User createUser(String email, String username, String passwordHash) {
//	        if (userRepository.findByEmail(email).isPresent()) {
//	            throw new RuntimeException("Email already exists");
//	        }
//
//	        User user = new User();
//	        user.setEmail(email);
//	        user.setUsername(username);
//	        user.setPasswordHash(passwordHash);
//
//	        return userRepository.save(user);
//	    }
//
//	    @Override
//	    public void assignRoleToUser(User user, Role.RoleName roleName) {
//	        Role role = roleRepository.findByRoleName(roleName)
//	                .orElseThrow(() -> new RuntimeException("Role not found"));
//
//	        UserRole userRole = new UserRole();
//	        userRole.setUser(user);
//	        userRole.setRole(role);
//
//	        userRoleRepository.save(userRole);
//	    }
//
//	    @Override
//	    public void grantPermissionToRole(Role.RoleName roleName, String permissionName) {
//	        Role role = roleRepository.findByRoleName(roleName)
//	                .orElseThrow(() -> new RuntimeException("Role not found"));
//
//	        Permission permission = permissionRepository.findByPermissionId(permissionName)
//	                .orElseThrow(() -> new RuntimeException("Permission not found"));
//
//	        RolePermission rolePermission = new RolePermission();
//	        rolePermission.setRole(role);
//	        rolePermission.setPermission(permission);
//
//	        rolePermissionRepository.save(rolePermission);
//	    }
//	    
//	    public UserResponse processUserDetails(Map<String, Object> userDetails) {
//			String email = (String) userDetails.get("email");
//			String username = (String) userDetails.get("name");
//			String picture = (String) userDetails.get("picture");
//
//			// Validate required fields
//			if (email == null || email.isEmpty()) {
//				throw new RuntimeException("Email is required");
//			}
//
//			// Use a fallback variable for username
//			String effectiveUsername = (username == null || username.isEmpty()) ? "Unknown User" : username;
//
//			// Check if the user already exists in the database
//			User user = userRepository.findByEmail(email).orElseGet(() -> {
//				// Create a new user if not found
//				User newUser = new User();
//				newUser.setEmail(email);
//				newUser.setUsername(effectiveUsername); // Use the fallback username here
//				newUser.setPasswordHash(""); // Google login users don’t need password storage
//				return userRepository.save(newUser);
//			});
//
//			// Assign a default role if no roles exist for the user
//			if (userRoleRepository.findByUser(user).isEmpty()) {
//				Role defaultRole = roleRepository.findByRoleName(Role.RoleName.CUSTOMER)
//						.orElseThrow(() -> new RuntimeException("Default role CUSTOMER not found"));
//				UserRole userRole = new UserRole();
//				userRole.setUser(user);
//				userRole.setRole(defaultRole);
//				userRoleRepository.save(userRole);
//			}
//
//			// Retrieve user roles and permissions
//			List<Role> roles = userRoleRepository.findByUser(user).stream().map(UserRole::getRole)
//					.collect(Collectors.toList());
//			List<String> permissions = roles.stream().flatMap(role -> rolePermissionRepository.findByRole(role).stream()) // Ensuring
//																															// this
//																															// returns
//																															// a
//																															// Stream<RolePermission>
//					.map(rolePermission -> rolePermission.getPermission().getPermissionName()).collect(Collectors.toList());
//
//			// Build the response DTO
//			UserResponse response = new UserResponse();
//			response.setUserId(user.getUserId());
//			response.setEmail(user.getEmail());
//			response.setUsername(user.getUsername());
//			response.setProfilePicture(picture);
//			response.setRoles(roles.stream().map(Role::getRoleName).collect(Collectors.toList()));
//			response.setPermissions(permissions);
//
//			return response;
//		}
//
//}
