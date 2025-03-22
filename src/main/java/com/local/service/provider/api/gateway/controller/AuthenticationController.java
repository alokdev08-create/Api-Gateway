package com.local.service.provider.api.gateway.controller;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import com.local.service.provider.api.gateway.service.TokenService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class AuthenticationController {
	private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);
	@Autowired
	private TokenService tokenService;

	@GetMapping("/")
	public String home() {
		return "Hello Welcome Alok Ranjan!!";
	}

	@GetMapping(value = "/getAccessToken", produces = "application/json")
	public ResponseEntity<Object> getAccessToken(@RequestParam("authCode") String authCode) {
		if (authCode == null || authCode.trim().isEmpty()) {
			return ResponseEntity.badRequest().body("Authorization code is required and cannot be empty.");
		}

		try {
			String accessToken = tokenService.accessToken(authCode);
			return ResponseEntity.ok(Map.of("accessToken", accessToken));
		} catch (IllegalArgumentException e) {
			return ResponseEntity.badRequest().body(Map.of("error", "Invalid request", "message", e.getMessage()));
		} catch (Exception e) {
			return ResponseEntity.internalServerError()
					.body(Map.of("error", "Internal Server Error", "message", e.getMessage()));
		}
	}

	@GetMapping(value = "/api/v1/fetchUserDetails", produces = "application/json")
	public ResponseEntity<?> fetchUserDetails(ServerWebExchange exchange) {
	    try {
	        // Extract Authorization header from ServerWebExchange
	        HttpHeaders headers = exchange.getRequest().getHeaders();
	        String authorizationHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);

	        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
	            throw new IllegalArgumentException("Authorization header must be present and start with 'Bearer '.");
	        }

	        // Extract the token and fetch user details
	        String accessToken = authorizationHeader.replace("Bearer ", "").trim();
	        Map<String, Object> userDetails = tokenService.fetchUserDetails(accessToken,exchange);

	       
	       return ResponseEntity.ok(userDetails);
	    } catch (IllegalArgumentException e) {
	        logger.error("Client error: {}", e.getMessage());
	        return ResponseEntity.badRequest().body(Map.of(
	            "error", "Invalid request",
	            "message", e.getMessage()
	        ));
	    } catch (Exception e) {
	        logger.error("Unexpected error: {}", e.getMessage(), e);
	        return ResponseEntity.internalServerError().body(Map.of(
	            "error", "Failed to fetch user details",
	            "message", e.getMessage()
	        ));
	    }
	}

}
