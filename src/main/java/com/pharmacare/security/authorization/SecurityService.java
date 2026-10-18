package com.pharmacare.security.authorization;

import org.springframework.security.core.Authentication;

public interface SecurityService {
    boolean hasAccess(String requiredRole);
    boolean canReadMember(Authentication authentication, Long memberId);
}
