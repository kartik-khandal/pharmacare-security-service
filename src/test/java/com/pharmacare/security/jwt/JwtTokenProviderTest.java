package com.pharmacare.security.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Verifies token type separation so refresh credentials cannot authorize API requests. */
class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider();
        // A plain unit test has no Spring context to inject configuration properties.
        ReflectionTestUtils.setField(jwtTokenProvider, "secret", "test-secret-that-is-long-enough-for-hmac");
        ReflectionTestUtils.setField(jwtTokenProvider, "expiration", 86_400_000L);
        ReflectionTestUtils.setField(jwtTokenProvider, "refreshExpiration", 604_800_000L);
        jwtTokenProvider.init();
    }

    @Test
    void accessTokensCannotBeUsedAsRefreshTokens() {
        String accessToken = jwtTokenProvider.generateToken("user", "USER");

        // A normal access token authorizes requests but cannot be exchanged for another token pair.
        assertTrue(jwtTokenProvider.validateToken(accessToken));
        assertFalse(jwtTokenProvider.validateRefreshToken(accessToken));
    }

    @Test
    void refreshTokensCannotBeUsedAsAccessTokens() {
        String refreshToken = jwtTokenProvider.generateRefreshToken("user", "USER");

        // Refresh credentials renew access, but must not grant direct access to protected resources.
        assertTrue(jwtTokenProvider.validateRefreshToken(refreshToken));
        assertFalse(jwtTokenProvider.validateToken(refreshToken));
    }
}
