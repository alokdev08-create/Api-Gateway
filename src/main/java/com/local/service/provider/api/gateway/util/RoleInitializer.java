//package com.local.service.provider.api.gateway.util;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.stereotype.Component;
//
//import com.local.service.provider.api.gateway.entity.Role;
//import com.local.service.provider.api.gateway.repository.RoleRepository;
//
//@Component
//public class RoleInitializer implements CommandLineRunner {
//
//	@Autowired
//	private RoleRepository roleRepository;
//
//	@Override
//	public void run(String... args) throws Exception {
//		initializeRole(Role.RoleName.CUSTOMER, "Default role for customers");
//		initializeRole(Role.RoleName.SERVICE_PROVIDER, "Role for service providers");
//		initializeRole(Role.RoleName.ADMIN, "Administrator role");
//	}
//
//	private void initializeRole(Role.RoleName roleName, String description) {
//		System.out.println("Initializing role: " + roleName); // Debug log
//
//		if (roleRepository.findByRoleName(roleName).isEmpty()) {
//			Role role = new Role();
//			role.setRoleName(roleName); // Correct enum constant
//			role.setDescription(description);
//			roleRepository.save(role);
//		}
//	}
//}
