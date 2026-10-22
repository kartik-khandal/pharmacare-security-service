package com.pharmacare.security.authentication.dto;

public record AuthResponse(
        String token,
        String refreshToken,
        String username,
        String role
) {
}
