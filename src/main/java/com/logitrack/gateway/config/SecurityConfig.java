package com.logitrack.gateway.config;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

/**
 * Configuración reactiva de seguridad para Spring Cloud Gateway.
 * Valida centralizadamente JWT RS256, aplica RBAC estricto según la matriz
 * y proporciona respuestas JSON normalizadas para errores 401 y 403.
 */ //----------------------------------------------------------1
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            ReactiveJwtDecoder jwtDecoder,
            ServerAuthenticationEntryPoint authenticationEntryPoint,
            ServerAccessDeniedHandler accessDeniedHandler,
            CorsConfigurationSource corsConfigurationSource) {
//-----------------------------------------------------------------3
        JwtAuthenticationConverter authConverter = new JwtAuthenticationConverter();
        authConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Object rolesClaim = jwt.getClaims().get("roles");
            if (!(rolesClaim instanceof Collection<?> roles)) {
                return List.<GrantedAuthority>of();
            }
            return roles.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();
        });
//--------------------------------------------------4-
        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeExchange(exchanges -> exchanges
                        // Endpoints públicos de autenticación y salud
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/login").permitAll()
                        .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()

                        // Endpoints de usuarios (security-service)
                        .pathMatchers(HttpMethod.POST, "/api/v1/users", "/api/v1/users/").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/api/v1/users/me").authenticated()
                        .pathMatchers(HttpMethod.GET, "/api/v1/users/*").hasRole("ADMIN")

                        // Endpoints de repartidores (courier-service)
                        .pathMatchers(HttpMethod.POST, "/api/v1/couriers", "/api/v1/couriers/").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/api/v1/couriers", "/api/v1/couriers/").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.PATCH, "/api/v1/couriers/*/estado").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/api/v1/couriers/*/disponibilidad").hasAnyRole("ADMIN", "REPARTIDOR")
                        .pathMatchers(HttpMethod.GET, "/api/v1/couriers/*").hasAnyRole("ADMIN", "REPARTIDOR")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/couriers/*").hasAnyRole("ADMIN", "REPARTIDOR")

                        // Endpoints de envíos (shipment-service)
                        .pathMatchers(HttpMethod.POST, "/api/v1/shipments", "/api/v1/shipments/").hasAnyRole("CLIENTE", "ADMIN")
                        .pathMatchers(HttpMethod.GET, "/api/v1/shipments", "/api/v1/shipments/").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/shipments/*/repartidor").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.PATCH, "/api/v1/shipments/*/cancelacion").hasAnyRole("ADMIN", "CLIENTE")
                        .pathMatchers(HttpMethod.PATCH, "/api/v1/shipments/*/estado").hasAnyRole("ADMIN", "REPARTIDOR")
                        .pathMatchers(HttpMethod.GET, "/api/v1/shipments/*", "/api/v1/shipments/seguimiento/*").hasAnyRole("ADMIN", "CLIENTE", "REPARTIDOR")

                        .anyExchange().denyAll()
                )//----------------------------------------5
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt
                                .jwtDecoder(jwtDecoder)
                                .jwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(authConverter))
                        )
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                );//--------------------------------

        return http.build();
    }

    @Bean//--------------------------------2
    ReactiveJwtDecoder reactiveJwtDecoder(
            ResourceLoader resourceLoader,
            @Value("${security.jwt.public-key-location:classpath:keys/public.pem}") String keyLocation,
            @Value("${security.jwt.issuer:logitrack-security}") String issuer) throws Exception {

        Resource resource = resourceLoader.getResource(keyLocation);
        RSAPublicKey publicKey;
        try (InputStream input = resource.getInputStream()) {
            publicKey = RsaKeyConverters.x509().convert(input);
        }

        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                .withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();

        // Invalid identity claims are authentication failures, before RBAC conversion.
        OAuth2TokenValidator<Jwt> identityValidator = jwt -> {
            try {
                String subject = jwt.getSubject();
                if (subject == null || !UUID.fromString(subject).toString().equals(subject)) {
                    throw new IllegalArgumentException("Invalid subject");
                }
                Object claim = jwt.getClaims().get("roles");
                if (!(claim instanceof List<?> roles) || roles.size() != 1
                        || !roles.stream().allMatch(role ->
                                role instanceof String && List.of("ADMIN", "CLIENTE", "REPARTIDOR").contains(role))
                        || jwt.getExpiresAt() == null) {
                    throw new IllegalArgumentException("Invalid identity claims");
                }
                return OAuth2TokenValidatorResult.success();
            } catch (IllegalArgumentException ex) {
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "Invalid identity claims", null));
            }
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer), identityValidator));
        return decoder;
    }
//---------------------------------------------------------------------------6
    @Bean
    ServerAuthenticationEntryPoint authenticationEntryPoint(ObjectMapper mapper) {
        return (exchange, ex) -> {
            var response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> body = Map.of(
                    "status", 401,
                    "error", "Unauthorized",
                    "mensaje", "Token ausente, inválido o expirado",
                    "timestamp", OffsetDateTime.now(ZoneOffset.UTC).toString()
            );

            try {
                byte[] bytes = mapper.writeValueAsString(body).getBytes(StandardCharsets.UTF_8);
                DataBuffer buffer = response.bufferFactory().wrap(bytes);
                return response.writeWith(Mono.just(buffer));
            } catch (JsonProcessingException e) {
                return Mono.error(e);
            }
        };
    }

    @Bean
    ServerAccessDeniedHandler accessDeniedHandler(ObjectMapper mapper) {
        return (exchange, denied) -> {
            var response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FORBIDDEN);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> body = Map.of(
                    "status", 403,
                    "error", "Forbidden",
                    "mensaje", "No tiene permisos para realizar esta operación",
                    "timestamp", OffsetDateTime.now(ZoneOffset.UTC).toString()
            );

            try {
                byte[] bytes = mapper.writeValueAsString(body).getBytes(StandardCharsets.UTF_8);
                DataBuffer buffer = response.bufferFactory().wrap(bytes);
                return response.writeWith(Mono.just(buffer));
            } catch (JsonProcessingException e) {
                return Mono.error(e);
            }
        };
    }
//------------------------------------------------------
    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${security.cors.allowed-origins:http://localhost:3000,http://localhost:5173}") List<String> origins) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION, HttpHeaders.CONTENT_TYPE, "Idempotency-Key"));
        config.setExposedHeaders(List.of("X-Total-Count", "X-Total-Pages"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
