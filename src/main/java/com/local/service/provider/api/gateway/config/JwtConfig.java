package com.local.service.provider.api.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtConfig {
	 @Bean
	    public JwtDecoder jwtDecoder() {
	        // Replace with your actual public key or JWK Set URI
	        String jwkSetUri = "https://www.googleapis.com/oauth2/v3/certs";

	        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
	    }
}
