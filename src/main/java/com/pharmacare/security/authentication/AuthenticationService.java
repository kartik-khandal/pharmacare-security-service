package com.pharmacare.security.authentication;

import com.pharmacare.security.authentication.dto.AuthResponse;
import com.pharmacare.security.authentication.dto.LoginRequest;
import com.pharmacare.security.authentication.dto.RegisterRequest;

public interface AuthenticationService {
    AuthResponse register(RegisterRequest request);
    AuthResponse login(LoginRequest request);
    AuthResponse refresh(String refreshToken);
}
