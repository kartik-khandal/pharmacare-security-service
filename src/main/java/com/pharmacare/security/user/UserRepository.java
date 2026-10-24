package com.pharmacare.security.user;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/** Spring Data derives these query implementations from the method names. */
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByGlobalUserId(java.util.UUID globalUserId);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
