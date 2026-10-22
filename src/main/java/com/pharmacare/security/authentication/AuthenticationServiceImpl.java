package com.pharmacare.security.authentication;

import com.pharmacare.security.authentication.dto.AuthResponse;
import com.pharmacare.security.authentication.dto.LoginRequest;
import com.pharmacare.security.authentication.dto.RegisterRequest;
import com.pharmacare.security.jwt.JwtTokenProvider;
import com.pharmacare.security.user.Role;
import com.pharmacare.security.user.User;
import com.pharmacare.security.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/** Coordinates account persistence, credential authentication, and JWT issuance. */
@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthenticationServiceImpl(UserRepository userRepository,
                                    PasswordEncoder passwordEncoder,
                                    AuthenticationManager authenticationManager,
                                    JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public AuthResponse register(RegisterRequest request) {
        // Check uniqueness before insert to return a clear validation error to the client.
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already exists");
        }

        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already exists");
        }

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        // Hash passwords before persistence; password hashes should never be reversible.
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(Role.USER);

        userRepository.save(user);

        return createAuthResponse(user);
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        // Delegate password verification to Spring Security instead of comparing hashes here.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

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
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return createAuthResponse(user);
    }

    private AuthResponse createAuthResponse(User user) {
        // Keep access and refresh lifetimes separate while issuing the pair together.
        String token = jwtTokenProvider.generateToken(user.getUsername(), user.getRole().name());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getUsername(), user.getRole().name());
        return new AuthResponse(token, refreshToken, user.getUsername(), user.getRole().name());
    }
}
