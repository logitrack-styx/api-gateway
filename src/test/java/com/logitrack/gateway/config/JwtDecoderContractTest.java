package com.logitrack.gateway.config;

import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises cryptographic verification and identity claims using ephemeral RSA keys.
 * No production credentials or tokens are persisted.
 * @author dominox45
 */
class JwtDecoderContractTest {
    @Test
    void verifiesSignatureIssuerExpirationAndIdentityClaims() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        var file = Files.createTempFile("jwt-public-", ".pem");
        try {
            Files.writeString(file, "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n");
            var decoder = new SecurityConfig().reactiveJwtDecoder(
                    new DefaultResourceLoader(), file.toUri().toString(), "logitrack-security");
            String subject = UUID.randomUUID().toString();
            Instant future = Instant.now().plusSeconds(3600);
            assertEquals(subject, decoder.decode(token(pair, "logitrack-security", subject,
                    List.of("ADMIN"), future)).block().getSubject());
            assertThrows(JwtException.class, () -> decoder.decode(token(pair, "wrong", subject,
                    List.of("ADMIN"), future)).block());
            assertThrows(JwtException.class, () -> decoder.decode(token(pair, "logitrack-security", subject,
                    List.of("ADMIN"), Instant.now().minusSeconds(120))).block());
            for (Object roles : List.of("ADMIN", List.of("UNKNOWN"), List.of(), List.of(1))) {
                assertThrows(JwtException.class, () -> decoder.decode(token(pair, "logitrack-security",
                        subject, roles, future)).block());
            }
            assertThrows(JwtException.class, () -> decoder.decode(token(pair, "logitrack-security",
                    "not-a-uuid", List.of("CLIENTE"), future)).block());
            KeyPair other = generator.generateKeyPair();
            assertThrows(JwtException.class, () -> decoder.decode(token(other, "logitrack-security",
                    subject, List.of("ADMIN"), future)).block());
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private String token(KeyPair pair, String issuer, String subject, Object roles, Instant expiration) {
        var key = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate()).build();
        var encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(subject)
                .issuedAt(Instant.now().minusSeconds(300)).expiresAt(expiration)
                .claim("roles", roles).build();
        return encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).getTokenValue();
    }
}
