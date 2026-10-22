package com.pharmacare.security.authorization;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

/** Implements resource-specific access decisions used by controller method security. */
@Service("securityService")
public class SecurityServiceImpl implements SecurityService {

    @Override
    public boolean hasAccess(String requiredRole) {
        // Not implemented yet: returning false keeps this unused check fail-closed.
        return false;
    }

    @Override
    public boolean canReadMember(Authentication authentication, Long memberId) {
        // Reject missing authentication before inspecting authorities.
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        // This sample grants member-read access to either role; production rules can compare ownership.
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority -> authority.equals("ROLE_USER") || authority.equals("ROLE_ADMIN"));
    }
}
