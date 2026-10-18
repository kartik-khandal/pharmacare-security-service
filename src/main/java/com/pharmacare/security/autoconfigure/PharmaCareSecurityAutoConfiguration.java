package com.pharmacare.security.autoconfigure;

import com.pharmacare.security.authentication.AuthenticationServiceImpl;
import com.pharmacare.security.authorization.SecurityServiceImpl;
import com.pharmacare.security.config.RoleConfig;
import com.pharmacare.security.config.SecurityConfiguration;
import com.pharmacare.security.jwt.JwtAuthenticationFilter;
import com.pharmacare.security.jwt.JwtTokenProvider;
import com.pharmacare.security.user.UserDetailsServiceImpl;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@AutoConfiguration
@ConditionalOnClass({
        SecurityConfiguration.class,
        JwtAuthenticationFilter.class,
        JwtTokenProvider.class,
        UserDetailsServiceImpl.class,
        AuthenticationServiceImpl.class,
        RoleConfig.class,
        SecurityServiceImpl.class
})
@EntityScan(basePackages = "com.pharmacare.security")
@EnableJpaRepositories(basePackages = "com.pharmacare.security")
@Import({
        SecurityConfiguration.class,
        RoleConfig.class,
        JwtTokenProvider.class,
        JwtAuthenticationFilter.class,
        UserDetailsServiceImpl.class,
        AuthenticationServiceImpl.class,
        SecurityServiceImpl.class
})
public class PharmaCareSecurityAutoConfiguration {
}
