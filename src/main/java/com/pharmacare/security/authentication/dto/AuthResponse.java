package com.pharmacare.security.authentication.dto;

/** Tokens and display identity returned after login, registration, or refresh. */
public record AuthResponse(
        // Short-lived credential sent as a Bearer token to protected endpoints.
        String token,
        // Longer-lived credential exchanged only at the refresh endpoint.
        String refreshToken,
        String username,
        String role
) {
}
