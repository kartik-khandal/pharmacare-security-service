package com.pharmacare.security.config;

import com.pharmacare.security.user.Role;
import com.pharmacare.security.user.User;
import com.pharmacare.security.user.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Supplies role-name helpers and initializes the development administrator account. */
@Configuration
public class RoleConfig {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public RoleConfig(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public String getAdminRole() {
        return Role.ADMIN.name();
    }

    public String getUserRole() {
        return Role.USER.name();
    }

    @Bean
    CommandLineRunner initRoles() {
        return args -> {
            // Seed only when absent, making startup idempotent; replace these demo credentials
            // with a secure provisioning process before deploying to production.
            if (userRepository.findByUsername("admin").isEmpty()) {
                User admin = new User();
                admin.setUsername("admin");
                admin.setEmail("admin@pharmacare.com");
                admin.setPassword(passwordEncoder.encode("admin123"));
                admin.setRole(Role.ADMIN);
                userRepository.save(admin);
            }
        };
    }
}
