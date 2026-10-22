package com.pharmacare.security.authorization;

import org.springframework.security.core.Authentication;

/** Contract for authorization checks invoked from method-security expressions. */
public interface SecurityService {
    boolean hasAccess(String requiredRole);
    boolean canReadMember(Authentication authentication, Long memberId);
}
