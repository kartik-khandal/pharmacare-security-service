package com.pharmacare.security.user;

import java.util.Optional;
import java.util.UUID;

/** Persistence port implemented by the API module so security code stays database-vendor agnostic. */
public interface UserAccountStore {
    UserAccount create(String username, String email, String encodedPassword, Role role);

    Optional<UserAccount> findByUsername(String username);

    Optional<UserAccount> findById(UUID userId);

    void updatePassword(UUID userId, String encodedPassword);

    void deactivate(UUID userId);
}
