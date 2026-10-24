package com.pharmacare.security.config;

import com.pharmacare.security.user.Role;
import org.springframework.context.annotation.Configuration;

/** Supplies role-name helpers; accounts must be provisioned through the global identity directory. */
@Configuration
public class RoleConfig {

    public String getAdminRole() {
        return Role.ADMIN.name();
    }

    public String getUserRole() {
        return Role.USER.name();
    }

}
