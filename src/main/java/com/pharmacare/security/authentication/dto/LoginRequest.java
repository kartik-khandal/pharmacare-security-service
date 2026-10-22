package com.pharmacare.security.authentication.dto;

import jakarta.validation.constraints.NotBlank;

/** Validated credentials accepted by the login endpoint. */
public record LoginRequest(
        @NotBlank(message = "Username is required") String username,
        @NotBlank(message = "Password is required") String password
) {
}
