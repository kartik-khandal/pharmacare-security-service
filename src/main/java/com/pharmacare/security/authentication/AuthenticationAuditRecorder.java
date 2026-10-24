package com.pharmacare.security.authentication;

import java.util.UUID;

/** Security-layer port for secret-free authentication audit events. */
public interface AuthenticationAuditRecorder {
    void recordLoginSucceeded(UUID userId);

    void recordLoginFailed();
}
