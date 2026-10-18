package com.pharmacare.security.authorization;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service("securityService")
public class SecurityServiceImpl implements SecurityService {

    @Override
    public boolean hasAccess(String requiredRole) {
        return false;
    }

    @Override
    public boolean canReadMember(Authentication authentication, Long memberId) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority -> authority.equals("ROLE_USER") || authority.equals("ROLE_ADMIN"));
    }
}

