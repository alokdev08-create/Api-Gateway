//package com.local.service.provider.api.gateway.config;
//
//import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
//import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
//import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
//
//import jakarta.servlet.http.HttpServletRequest;
//
//import java.util.Map;
//
//public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
//
//	private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;
//
//    public CustomAuthorizationRequestResolver(DefaultOAuth2AuthorizationRequestResolver defaultResolver) {
//        this.defaultResolver = defaultResolver;
//    }
//
//    @Override
//    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
//        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
//        return customizeAuthorizationRequest(authorizationRequest);
//    }
//
//    @Override
//    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
//        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request, clientRegistrationId);
//        return customizeAuthorizationRequest(authorizationRequest);
//    }
//
//    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
//        if (authorizationRequest == null) {
//            return null;
//        }
//
//        // Add "access_type=offline" to obtain a refresh token
//        Map<String, Object> additionalParameters = authorizationRequest.getAdditionalParameters();
//        additionalParameters.put("access_type", "offline");
//
//        return OAuth2AuthorizationRequest.from(authorizationRequest)
//                .additionalParameters(additionalParameters)
//                .build();
//    }
//}
