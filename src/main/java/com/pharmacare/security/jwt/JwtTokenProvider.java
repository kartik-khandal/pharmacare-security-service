package com.pharmacare.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

/** Creates and verifies signed JWTs used for short-lived access and longer-lived refresh credentials. */
@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration:86400000}")
    private long expiration;

    @Value("${jwt.refresh-expiration:604800000}")
    private long refreshExpiration;

    private static final String TOKEN_TYPE_CLAIM = "token_type";
    private static final String ACCESS_TOKEN_TYPE = "access";
    private static final String REFRESH_TOKEN_TYPE = "refresh";

    // Both token types use the same signing key; the type claim prevents a refresh token
    // from being accepted by the access-token filter (and vice versa).
    private Key key;

    @PostConstruct
    public void init() {
        // Derive the HMAC signing key once when Spring creates this component.
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateToken(String username, String role) {
        return generateToken(username, role, expiration, ACCESS_TOKEN_TYPE);
    }

    // Refresh tokens live longer and are only exchanged at the refresh endpoint.
    public String generateRefreshToken(String username, String role) {
        return generateToken(username, role, refreshExpiration, REFRESH_TOKEN_TYPE);
    }

    private String generateToken(String username, String role, long tokenExpiration, String tokenType) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + tokenExpiration);
        // JWT claims carry identity and token purpose; the signature detects tampering.
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .claim(TOKEN_TYPE_CLAIM, tokenType)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsernameFromToken(String token) {
        // Parsing with the signing key verifies the JWT before its subject is trusted.
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            // Parsing verifies the signature and expiry before trusting any claims.
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            String tokenType = claims.get(TOKEN_TYPE_CLAIM, String.class);
            return tokenType == null || ACCESS_TOKEN_TYPE.equals(tokenType);
        } catch (Exception ex) {
            return false;
        }
    }

    public boolean validateRefreshToken(String token) {
        try {
            // A valid signature is not enough: the token must explicitly be a refresh token.
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return REFRESH_TOKEN_TYPE.equals(claims.get(TOKEN_TYPE_CLAIM, String.class));
        } catch (Exception ex) {
            return false;
        }
    }
}
