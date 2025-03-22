package com.local.service.provider.api.gateway.exception;

public class OAuthException  extends RuntimeException {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public OAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}