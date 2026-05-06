package com.banking.api_gateway.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

	@Autowired
	private JwtUtils jwtUtils;

	public JwtAuthFilter() {
		super(Config.class);

	}

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) -> {

			String path = exchange.getRequest().getURI().getPath();

			if (path.contains("/api/auth/register") || path.contains("/api/auth/login")
					|| path.contains("/api/auth/loginjwt")) {
				return chain.filter(exchange);
			}

			if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "No Authorization header found!", HttpStatus.UNAUTHORIZED);
			}
			String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
			if (authHeader == null || !authHeader.startsWith("Bearer ")) {
				return onError(exchange, "Invalid Authorization header format!", HttpStatus.UNAUTHORIZED);
			}

			String token = authHeader.substring(7);

			if (!jwtUtils.validateToken(token)) {
				return onError(exchange, "Invalid or Expired token!", HttpStatus.UNAUTHORIZED);
			}
			String role = jwtUtils.extractRole(token);
			String userName = jwtUtils.extractUserName(token);

			if (path.contains("/api/loans/approve") || path.contains("/api/loans/reject")
					|| path.contains("/api/account") && exchange.getRequest().getMethod().toString().equals("POST")) {
				if (!role.equals("ROLE_ADMIN")) {
					return onError(exchange, "Access Denied! Admin only endpoint!", HttpStatus.FORBIDDEN);
				}
			}
			exchange.getRequest().mutate().header("X-UserName", userName).header("X-Role", role).build();

			return chain.filter(exchange);
		};
	}

	private Mono<Void> onError(ServerWebExchange exchange, String string, HttpStatus unauthorized) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(unauthorized);
		response.getHeaders().add("Content-Type", "application/json");

		String body = "{\"status\":" + unauthorized.value() + ",\"message\":\"" + string + "\"" + ",\"timestamp\":\""
				+ java.time.LocalDateTime.now() + "\"}";

		DataBuffer buffer = response.bufferFactory().wrap(body.getBytes());
		return response.writeWith(Mono.just(buffer));
	}

	public static class Config {

	}
}
