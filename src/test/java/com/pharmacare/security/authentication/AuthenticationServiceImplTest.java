package com.pharmacare.security.authentication;

import com.pharmacare.security.authentication.dto.LoginRequest;
import com.pharmacare.security.authentication.dto.RegisterRequest;
import com.pharmacare.security.jwt.JwtTokenProvider;
import com.pharmacare.security.user.Role;
import com.pharmacare.security.user.UserAccount;
import com.pharmacare.security.user.UserAccountStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationServiceImplTest {

    private FakeAccountStore accountStore;
    private FakeAuditRecorder auditRecorder;
    private JwtTokenProvider jwtTokenProvider;
    private AuthenticationServiceImpl authenticationService;

    @BeforeEach
    void setUp() {
        accountStore = new FakeAccountStore();
        auditRecorder = new FakeAuditRecorder();
        PasswordEncoder passwordEncoder = new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return "encoded:" + rawPassword;
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return encodedPassword.equals(encode(rawPassword));
            }
        };
        jwtTokenProvider = new JwtTokenProvider();
        ReflectionTestUtils.setField(jwtTokenProvider, "secret",
                "authentication-test-key-with-at-least-32-bytes");
        ReflectionTestUtils.setField(jwtTokenProvider, "expiration", 86_400_000L);
        ReflectionTestUtils.setField(jwtTokenProvider, "refreshExpiration", 604_800_000L);
        jwtTokenProvider.init();

        authenticationService = new AuthenticationServiceImpl(
                accountStore,
                auditRecorder,
                passwordEncoder,
                authentication -> {
                    UsernamePasswordAuthenticationToken submitted =
                            (UsernamePasswordAuthenticationToken) authentication;
                    UserAccount account = accountStore.account;
                    if (account == null || !passwordEncoder.matches(
                            submitted.getCredentials().toString(), account.passwordHash())) {
                        throw new BadCredentialsException("Bad credentials");
                    }
                    return UsernamePasswordAuthenticationToken.authenticated(
                            submitted.getPrincipal(), null,
                            List.of(new SimpleGrantedAuthority("ROLE_" + account.role().name())));
                },
                jwtTokenProvider);
    }

    @Test
    void registrationCanBeFollowedImmediatelyByLoginAndBothReturnTokenPairs() {
        var registered = authenticationService.register(
                new RegisterRequest("member", "member@example.test", "password123"));
        var login = authenticationService.login(new LoginRequest("member", "password123"));

        assertEquals("member", registered.username());
        assertTrue(jwtTokenProvider.validateToken(registered.token()));
        assertTrue(jwtTokenProvider.validateRefreshToken(registered.refreshToken()));
        assertEquals("member", login.username());
        assertEquals(1, auditRecorder.successfulLoginCount);
        assertEquals(0, auditRecorder.failedLoginCount);
    }

    @Test
    void failedLoginRecordsOnlyAFailureEventAndPreservesAuthenticationFailure() {
        assertThrows(BadCredentialsException.class,
                () -> authenticationService.login(new LoginRequest("unknown", "wrong-password")));

        assertEquals(1, auditRecorder.failedLoginCount);
        assertEquals(0, auditRecorder.successfulLoginCount);
    }

    @Test
    void refreshRequiresRefreshTokenAndRejectsDeactivatedAccounts() {
        authenticationService.register(new RegisterRequest("member", "member@example.test", "password123"));
        String refreshToken = jwtTokenProvider.generateRefreshToken("member", Role.USER.name());
        String accessToken = jwtTokenProvider.generateToken("member", Role.USER.name());

        assertTrue(jwtTokenProvider.validateRefreshToken(
                authenticationService.refresh(refreshToken).refreshToken()));
        assertThrows(IllegalArgumentException.class, () -> authenticationService.refresh(accessToken));

        accountStore.account = new UserAccount(accountStore.account.userId(), "member", "member@example.test",
                "encoded:password123", Role.USER, false);
        assertThrows(IllegalArgumentException.class, () -> authenticationService.refresh(refreshToken));
    }

    private static final class FakeAccountStore implements UserAccountStore {
        private UserAccount account;

        @Override
        public UserAccount create(String username, String email, String encodedPassword, Role role) {
            account = new UserAccount(UUID.randomUUID(), username, email, encodedPassword, role, true);
            return account;
        }

        @Override
        public Optional<UserAccount> findByUsername(String username) {
            return account != null && account.username().equals(username) ? Optional.of(account) : Optional.empty();
        }

        @Override
        public Optional<UserAccount> findById(UUID userId) {
            return account != null && account.userId().equals(userId) ? Optional.of(account) : Optional.empty();
        }

        @Override
        public void updatePassword(UUID userId, String encodedPassword) {
            account = new UserAccount(userId, account.username(), account.email(),
                    encodedPassword, account.role(), account.active());
        }

        @Override
        public void deactivate(UUID userId) {
            account = new UserAccount(userId, account.username(), account.email(),
                    account.passwordHash(), account.role(), false);
        }
    }

    private static final class FakeAuditRecorder implements AuthenticationAuditRecorder {
        private int successfulLoginCount;
        private int failedLoginCount;

        @Override
        public void recordLoginSucceeded(UUID userId) {
            successfulLoginCount++;
        }

        @Override
        public void recordLoginFailed() {
            failedLoginCount++;
        }
    }
}
