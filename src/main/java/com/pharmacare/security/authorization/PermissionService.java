package com.pharmacare.security.authorization;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/** Helper for checking whether the current request has a named role authority. */
@Service
public class PermissionService {

    public boolean hasPermission(String requiredRole) {
        // The security context is request-scoped; deny by default when no authenticated principal exists.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        return authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_" + requiredRole));
    }
}
