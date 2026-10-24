package com.pharmacare.security.user;

import java.util.UUID;

/** Globally unique directory entry used to find the shard containing an account. */
public record UserIdentity(UUID userId, String username, String email, String shardId) {
}
