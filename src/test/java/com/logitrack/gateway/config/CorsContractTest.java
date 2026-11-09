package com.logitrack.gateway.config;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

/**
 * Verifies the Gateway CORS policy for Sprint 4 browser requests.
 * @author dominox45
 */
class CorsContractTest {
    private static final String ORIGIN = "http://localhost:5173";
    private static final String HEADERS = "Authorization, Content-Type, Idempotency-Key";

    private final SecurityConfig config = new SecurityConfig();
    private final WebTestClient client = WebTestClient.bindToWebHandler(exchange -> {
                exchange.getResponse().getHeaders().set("X-Total-Count", "1");
                exchange.getResponse().getHeaders().set("X-Total-Pages", "1");
                return exchange.getResponse().setComplete();
            })
            .webFilter(new WebFilterChainProxy(config.springSecurityFilterChain(
                    ServerHttpSecurity.http(),
                    token -> Mono.just(Jwt.withTokenValue(token).header("alg", "RS256")
                            .subject("0c488b21-305b-4697-a17f-4186067834de")
                            .claim("roles", List.of(token)).build()),
                    new org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint(),
                    new org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler(),
                    config.corsConfigurationSource(List.of(ORIGIN)))))
            .configureClient()
            .baseUrl("http://localhost:8066")
            .build();

    @Test
    void acceptsPreflightsForAllIdempotentPosts() {
        for (String path : List.of("/api/v1/payments/quotes", "/api/v1/payments/checkouts",
                "/api/v1/shipments/0c488b21-305b-4697-a17f-4186067834de/assignment-requests")) {
            client.options().uri(path)
                    .header(HttpHeaders.ORIGIN, ORIGIN)
                    .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, HEADERS)
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN)
                    .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, HEADERS);
        }
    }

    @Test
    void rejectsUnlistedOrigin() {
        client.options().uri("/api/v1/payments/quotes")
                .header(HttpHeaders.ORIGIN, "https://hostile.example")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
    }

    @Test
    void exposesPaginationHeaders() {
        client.get().uri("/api/v1/shipments")
                .header(HttpHeaders.ORIGIN, ORIGIN)
                .headers(headers -> headers.setBearerAuth("ADMIN"))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "X-Total-Count, X-Total-Pages");
    }

    @Test
    void preservesAuthenticationAndRoleChecks() {
        client.get().uri("/api/v1/shipments").header(HttpHeaders.ORIGIN, ORIGIN)
                .exchange().expectStatus().isUnauthorized();
        client.get().uri("/api/v1/shipments").header(HttpHeaders.ORIGIN, ORIGIN)
                .headers(headers -> headers.setBearerAuth("CLIENTE"))
                .exchange().expectStatus().isForbidden();
    }
}
