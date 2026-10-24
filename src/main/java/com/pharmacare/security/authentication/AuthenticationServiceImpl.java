package com.pharmacare.security.authentication;

import com.pharmacare.security.authentication.dto.AuthResponse;
import com.pharmacare.security.authentication.dto.LoginRequest;
import com.pharmacare.security.authentication.dto.RegisterRequest;
import org.springframework.security.core.AuthenticationException;
import com.pharmacare.security.jwt.JwtTokenProvider;
import com.pharmacare.security.user.Role;
import com.pharmacare.security.user.UserAccount;
import com.pharmacare.security.user.UserAccountStore;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/** Coordinates account persistence, credential authentication, and JWT issuance. */
@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserAccountStore userAccountStore;
    private final AuthenticationAuditRecorder auditRecorder;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthenticationServiceImpl(UserAccountStore userAccountStore,
                                    AuthenticationAuditRecorder auditRecorder,
                                    PasswordEncoder passwordEncoder,
                                    AuthenticationManager authenticationManager,
                                    JwtTokenProvider jwtTokenProvider) {
        this.userAccountStore = userAccountStore;
        this.auditRecorder = auditRecorder;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public AuthResponse register(RegisterRequest request) {
        // Hash passwords before persistence; password hashes should never be reversible.
        UserAccount user = userAccountStore.create(
                request.username(), request.email(), passwordEncoder.encode(request.password()), Role.USER);
        return createAuthResponse(user);
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        // Delegate password verification to Spring Security instead of comparing hashes here.
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );
        } catch (AuthenticationException ex) {
            auditRecorder.recordLoginFailed();
            throw ex;
        }

        UserAccount user = userAccountStore.findByUsername(request.username())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        auditRecorder.recordLoginSucceeded(user.userId());
        return createAuthResponse(user);
    }

    @Override
    public AuthResponse refresh(String refreshToken) {
        // A refresh token proves the prior login session; it is not itself API authorization.
        if (!jwtTokenProvider.validateRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }

        // Reload the user so new access tokens use the current account and role data.
        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        UserAccount user = userAccountStore.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (!user.active()) {
            throw new IllegalArgumentException("User account is inactive");
        }

        return createAuthResponse(user);
    }

    private AuthResponse createAuthResponse(UserAccount user) {
        // Keep access and refresh lifetimes separate while issuing the pair together.
        String token = jwtTokenProvider.generateToken(user.username(), user.role().name());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.username(), user.role().name());
        return new AuthResponse(token, refreshToken, user.username(), user.role().name());
    }
}
