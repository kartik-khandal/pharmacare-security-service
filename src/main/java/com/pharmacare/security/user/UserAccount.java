package com.pharmacare.security.user;

import java.util.UUID;

/** Security-facing account view; storage and shard routing are supplied by the API application. */
public record UserAccount(
        UUID userId,
        String username,
        String email,
        String passwordHash,
        Role role,
        boolean active
) {
}
