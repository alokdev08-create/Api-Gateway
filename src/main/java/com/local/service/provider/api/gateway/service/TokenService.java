package com.local.service.provider.api.gateway.service;

import java.net.URL;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;

import com.local.service.provider.api.gateway.entity.LoginHistory;
import com.local.service.provider.api.gateway.entity.Permission;
import com.local.service.provider.api.gateway.entity.Role;
import com.local.service.provider.api.gateway.entity.RolePermission;
import com.local.service.provider.api.gateway.entity.User;
import com.local.service.provider.api.gateway.entity.UserPermission;
import com.local.service.provider.api.gateway.entity.UserProfile;
import com.local.service.provider.api.gateway.entity.UserRole;
import com.local.service.provider.api.gateway.model.UserResponse;
import com.local.service.provider.api.gateway.repository.LoginHistoryRepository;
import com.local.service.provider.api.gateway.repository.PermissionRepository;
import com.local.service.provider.api.gateway.repository.RolePermissionRepository;
import com.local.service.provider.api.gateway.repository.RoleRepository;
import com.local.service.provider.api.gateway.repository.UserPermissionRepository;
import com.local.service.provider.api.gateway.repository.UserProfileRepository;
import com.local.service.provider.api.gateway.repository.UserRepository;
import com.local.service.provider.api.gateway.repository.UserRoleRepository;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class TokenService {
	private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%&*!";
	private static final int PASSWORD_LENGTH = 12;
	private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

	@Value("${spring.security.oauth2.client.registration.google.client-id}")
	private String clientId;

	@Value("${spring.security.oauth2.client.registration.google.client-secret}")
	private String clientSecret;

	@Value("${spring.security.oauth2.client.provider.google.token-uri}")
	private String tokenUri;

	@Autowired
	private RestTemplate restTemplate;

	@Value("${app.google.redirect-uri}")
	private String redirectUrl;

	@Value("${token.url}")
	private String tokenUrl;
	@Value("${user.info.url}")
	private String userInfo;

	private static final String GOOGLE_JWK_URL = "https://www.googleapis.com/oauth2/v3/certs";
	private final String CLIENT_ID = clientId;

//	@Autowired
//	private UserService userService;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private UserRoleRepository userRoleRepository; // Correctly added

	@Autowired
	private RolePermissionRepository rolePermissionRepository; // Correctly added
	
	@Autowired 
	private UserPermissionRepository userPermissionRepository;
	@Autowired 
	private PermissionRepository permissionRepository;
	
	@Autowired 
	private UserProfileRepository userProfileRepository;
	
	@Autowired 
	private LoginHistoryRepository loginHistoryRepository;

	public String accessToken(String code) {
		try {
			MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
			params.add("code", code);
			params.add("client_id", clientId);
			params.add("client_secret", clientSecret);
			params.add("redirect_uri", redirectUrl);
			params.add("grant_type", "authorization_code");
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
			logger.info("Sending request to token endpoint...");
			ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, request, Map.class);

			if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
				logger.error("Failed to retrieve access token. HTTP Status: {}, Response: {}",
						tokenResponse.getStatusCode(), tokenResponse.getBody());
				throw new RuntimeException("Failed to retrieve access token. Please check the provided parameters.");
			}
			Map<String, Object> responseBody = tokenResponse.getBody();
			if (responseBody == null || !responseBody.containsKey("id_token")) {
				logger.error("id_token is missing in the token response: {}", responseBody);
				throw new RuntimeException("id_token not found in the token response.");
			}
			return (String) responseBody.get("id_token");

		} catch (IllegalArgumentException e) {
			logger.error("Validation error: {}", e.getMessage());
			throw e;
		} catch (Exception e) {
			logger.error("Exception occurred while fetching access token or user info", e);
			throw new RuntimeException("Unable to fetch access token: " + e.getMessage(), e);
		}
	}

	/**
	 * Validates the ID token and extracts user details (email, name, picture,
	 * etc.).
	 *
	 * @param idToken The ID token to validate.
	 * @return A Map containing user details.
	 */
	public Map<String, Object> fetchUserDetails(String idToken,ServerWebExchange exchange) {
		try {
			logger.info("Parsing the ID token...");

			// Parse the ID token
			SignedJWT signedJWT = SignedJWT.parse(idToken);

			logger.info("Fetching Google's public JWKs...");
			// Fetch Google's public JWK set
			JWKSet jwkSet = JWKSet.load(new URL(GOOGLE_JWK_URL));

			// Extract the Key ID from the token header
			String keyID = signedJWT.getHeader().getKeyID();
			JWK jwk = jwkSet.getKeyByKeyId(keyID);

			if (jwk == null) {
				throw new RuntimeException("JWK not found for Key ID: " + keyID);
			}

			// Validate the JWK is an RSA key and extract the public key
			if (!(jwk instanceof RSAKey)) {
				throw new RuntimeException("JWK is not an RSA key");
			}
			RSAPublicKey rsaPublicKey = ((RSAKey) jwk).toRSAPublicKey();

			logger.info("Validating the JWT signature and claims...");
			// Configure the JWT processor
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector((header, context) -> Collections.singletonList(rsaPublicKey));

			// Process and validate the token claims
			JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);

			// Verify token claims: Issuer and Audience
			String issuer = claims.getIssuer();
			if (!"https://accounts.google.com".equals(issuer)) {
				logger.error("Invalid issuer: {}", issuer);
				throw new RuntimeException("Invalid issuer: " + issuer);
			}

			if (!claims.getAudience()
					.contains("1039965862847-pbebuofut4gvv56spq1m9tp6o9aflhg5.apps.googleusercontent.com")) {
				logger.error("Invalid audience: {}", claims.getAudience());
				throw new RuntimeException("Invalid audience: " + claims.getAudience());
			}

			logger.info("Token validated successfully. Extracting user details...");

			// Extract user details from claims with null-safe checks
			Map<String, Object> userDetails = new HashMap<>();
			userDetails.put("email",
					claims.getStringClaim("email") != null ? claims.getStringClaim("email") : "Not provided");
			userDetails.put("email_verified",
					claims.getBooleanClaim("email_verified") != null ? claims.getBooleanClaim("email_verified")
							: false);
			userDetails.put("name",
					claims.getStringClaim("name") != null ? claims.getStringClaim("name") : "Not provided");
			userDetails.put("picture",
					claims.getStringClaim("picture") != null ? claims.getStringClaim("picture") : "Not provided");

			// Process and store user details
			UserResponse userResponse = processUserDetails(userDetails,exchange);

			// Prepare structured response to return
			Map<String, Object> response = new HashMap<>();
			response.put("user", userResponse);

			return response;

		} catch (ParseException e) {
			logger.error("Error parsing the ID token", e);
			throw new RuntimeException("Error parsing the ID token: " + e.getMessage(), e);
		} catch (Exception e) {
			logger.error("Unexpected error occurred while validating the ID token", e);
			throw new RuntimeException("Error validating the ID token: " + e.getMessage(), e);
		}
	}


	public UserResponse processUserDetails(Map<String, Object> userDetails, ServerWebExchange exchange) {
	    // Extract IP address and device information from ServerHttpRequest
	    ServerHttpRequest request = exchange.getRequest();
	    String ipAddress = getClientIpAddress(request);
	    String deviceInfo = getDeviceInfo(request);

	    String email = (String) userDetails.get("email");
	    String username = (String) userDetails.get("name");
	    String picture = (String) userDetails.get("picture");

	    // Validate required fields
	    if (email == null || email.isEmpty()) {
	        throw new RuntimeException("Email is required");
	    }

	    // Use a fallback variable for username
	    String effectiveUsername = (username == null || username.isEmpty()) ? "Unknown User" : username;

	    // Check if the user already exists in the database
	    User user = userRepository.findByEmail(email).orElseGet(() -> {
	        // Create a new user if not found
	        User newUser = new User();
	        newUser.setEmail(email);
	        newUser.setUsername(effectiveUsername); // Use the fallback username here
	        newUser.setPasswordHash(generateRandomPassword()); // Google login users don’t need password storage
	        return userRepository.save(newUser);
	    });

	    // Step 1: Create or Update the UserProfile
	    createOrUpdateUserProfile(user, effectiveUsername, null, null, picture);

	    // Step 2: Log the Login History
	    logUserLogin(user, ipAddress, deviceInfo);

	    // Step 3: Assign roles and permissions to the user
	    initializePermissionsAndAssignToUser(user);

	    // Step 4: Retrieve user roles after initializing roles and permissions
	    List<Role> roles = userRoleRepository.findByUser(user).stream()
	            .map(UserRole::getRole)
	            .collect(Collectors.toList());

	    // Step 5: Retrieve permissions from roles
	    List<String> permissions = roles.stream()
	            .flatMap(role -> rolePermissionRepository.findByRole(role).stream())
	            .map(rolePermission -> rolePermission.getPermission().getPermissionName())
	            .collect(Collectors.toList());

	    // Step 6: Build the UserResponse DTO
	    UserResponse response = new UserResponse();
	    response.setUserId(user.getUserId());
	    response.setEmail(user.getEmail());
	    response.setUsername(user.getUsername());
	    response.setProfilePicture(picture);
	    response.setRoles(roles.stream().map(Role::getRoleName).collect(Collectors.toList()));
	    response.setPermissions(permissions);

	    return response;
	}

	private String getClientIpAddress(ServerHttpRequest request) {
	    // Extract the IP address
	    String ipAddress = request.getHeaders().getFirst("X-Forwarded-For");
	    if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
	        ipAddress = request.getRemoteAddress().getAddress().getHostAddress();
	    }
	    return ipAddress;
	}

	private String getDeviceInfo(ServerHttpRequest request) {
	    // Extract the User-Agent header for device information
	    return request.getHeaders().getFirst("User-Agent");
	}

	private void setClientInfo(HttpServletRequest request, User user) {
		String ipAddress = getClientIpAddress(request);

        // Retrieve the client's device information from the User-Agent header
        String deviceInfo = getDeviceInfo(request);
	    // Step 2: Log the Login History
	    logUserLogin(user, ipAddress, deviceInfo);
	}  
	    

	private String getClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }
        return ipAddress;
    }

    private String getDeviceInfo(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }
	

	public void initializePermissionsAndAssignToUser(User user) {
	    // Step 1: Define hardcoded permissions
	    List<String> hardcodedPermissions = Arrays.asList("READ", "WRITE", "ADMIN");

	    // Step 2: Check and save permissions in the database
	    for (String permissionName : hardcodedPermissions) {
	        permissionRepository.findByPermissionName(permissionName).orElseGet(() -> {
	            Permission newPermission = new Permission();
	            newPermission.setPermissionName(permissionName);
	            return permissionRepository.save(newPermission); // Save to DB if not exists
	        });
	    }

	    // Step 3: Assign permissions to roles (example: assigning READ/WRITE to the CUSTOMER role)
	    Role customerRole = roleRepository.findByRoleName(Role.RoleName.CUSTOMER)
	            .orElseThrow(() -> new RuntimeException("Role CUSTOMER not found"));

	    // Map permissions to the CUSTOMER role
	    List<String> customerPermissions = Arrays.asList("READ", "WRITE");
	    for (String permissionName : customerPermissions) {
	        Permission permission = permissionRepository.findByPermissionName(permissionName)
	                .orElseThrow(() -> new RuntimeException("Permission " + permissionName + " not found"));

	        if (!rolePermissionRepository.existsByRoleAndPermission(customerRole, permission)) {
	            RolePermission rolePermission = new RolePermission();
	            rolePermission.setRole(customerRole);
	            rolePermission.setPermission(permission);
	            rolePermissionRepository.save(rolePermission);
	        }
	    }

	    // Step 4: Check and assign roles to the user if not already assigned
	    if (userRoleRepository.findByUser(user).isEmpty()) {
	        UserRole userRole = new UserRole();
	        userRole.setUser(user);
	        userRole.setRole(customerRole);
	        userRoleRepository.save(userRole);
	    }

	    // Step 5: Assign permissions to the user based on their roles
	    List<Role> userRoles = userRoleRepository.findByUser(user).stream()
	            .map(UserRole::getRole)
	            .collect(Collectors.toList());

	    for (Role role : userRoles) {
	        List<RolePermission> rolePermissions = rolePermissionRepository.findByRole(role);
	        for (RolePermission rolePermission : rolePermissions) {
	            Permission permission = rolePermission.getPermission();

	            // Ensure the permission is assigned to the user
	            if (!userPermissionRepository.existsByUserAndPermission(user, permission)) {
	                UserPermission userPermission = new UserPermission();
	                userPermission.setUser(user);
	                userPermission.setPermission(permission);
	                userPermissionRepository.save(userPermission);
	            }
	        }
	    }
	}
	
	public static String generateRandomPassword() {
		SecureRandom random = new SecureRandom();
		StringBuilder password = new StringBuilder(PASSWORD_LENGTH);
		for (int i = 0; i < PASSWORD_LENGTH; i++) {
			int index = random.nextInt(CHARACTERS.length());
			password.append(CHARACTERS.charAt(index));
		}

		return password.toString();
	}
	
	
	public void createOrUpdateUserProfile(User user, String fullName, String phoneNumber, String address, String profileImageUrl) {
	    Optional<UserProfile> existingProfile = userProfileRepository.findByUserUserId(user.getUserId());

	    if (existingProfile.isPresent()) {
	        UserProfile profile = existingProfile.get();
	        profile.setFullName(fullName);
	        profile.setPhoneNumber(phoneNumber);
	        profile.setAddress(address);
	        profile.setProfileImageUrl(profileImageUrl);
	        userProfileRepository.save(profile);
	    } else {
	        UserProfile newProfile = new UserProfile();
	        newProfile.setUser(user);
	        newProfile.setFullName(fullName);
	        newProfile.setPhoneNumber(phoneNumber);
	        newProfile.setAddress(address);
	        newProfile.setProfileImageUrl(profileImageUrl);
	        userProfileRepository.save(newProfile);
	    }
	}
	
	
	public void logUserLogin(User user, String ipAddress, String deviceInfo) {
	    LoginHistory loginHistory = new LoginHistory();
	    loginHistory.setUser(user);
	    loginHistory.setIpAddress(ipAddress);
	    loginHistory.setDeviceInfo(deviceInfo);
	    loginHistory.setLoginTime(LocalDateTime.now());
	    loginHistoryRepository.save(loginHistory);
	}

}
