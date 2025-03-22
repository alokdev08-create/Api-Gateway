package com.local.service.provider.api.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

	  /**
     * Configures the security filters for the application.
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/welcome", "/oauth2/**", "/getAccessToken").permitAll() // Public endpoints
                .pathMatchers("/api/v1/**").authenticated() // Secure /api/v1/** endpoints
                .anyExchange().authenticated() // Secure all other endpoints
            )
            .oauth2Login() // Enable OAuth2 Login
            .and()
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs") // Validate JWT tokens using Google's JWKs
                )
            )
            .cors() // Enable CORS
            .and()
            .csrf().disable() // Disable CSRF protection for APIs
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((exchange, ex) -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                })
            ); // Removed HTTPS redirection

        return http.build();
    }

    /**
     * Configures CORS settings for the application.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // Allow credentials and cookies
        config.addAllowedOriginPattern("*"); // Allow all origins for local testing (restrict in production)
        config.addAllowedMethod("*"); // Allow all HTTP methods
        config.addAllowedHeader("*"); // Allow all headers
        config.addExposedHeader("Authorization"); // Expose Authorization header
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
