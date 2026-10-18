package com.pharmacare.security.authentication.dto;

public record AuthResponse(
        String token,
        String username,
        String role
) {
}

