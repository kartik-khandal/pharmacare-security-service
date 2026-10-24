package com.pharmacare.security.user;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/** Bridges shard-aware account lookup to the principal model expected by Spring Security. */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserAccountStore userAccountStore;

    public UserDetailsServiceImpl(UserAccountStore userAccountStore) {
        this.userAccountStore = userAccountStore;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // The store resolves the identity directory first, then reads the selected shard's primary.
        UserAccount user = userAccountStore.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return new org.springframework.security.core.userdetails.User(
                user.username(),
                user.passwordHash(),
                user.active(),
                true,
                true,
                true,
                // Role names are prefixed as Spring Security authorities for role-based checks.
                List.of(new SimpleGrantedAuthority("ROLE_" + user.role().name()))
        );
    }
}
