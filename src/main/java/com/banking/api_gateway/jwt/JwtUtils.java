package com.banking.api_gateway.jwt;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {

	@Value("${jwt.secret}")
	private String secret;

	public boolean validateToken(String token) {
		try {
			getClaims(token);
			return !isTokenExpired(token);
		} catch (Exception e) {
			return false;
		}
	}

	public String extractUserName(String token) {
		return getClaims(token).getSubject();
	}

	public String extractRole(String token) {
		return getClaims(token).get("role", String.class);
	}

	private boolean isTokenExpired(String token) {
		return getClaims(token).getExpiration().before(new Date());
	}

	private Claims getClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getKey()).build().parseClaimsJws(token).getBody();
	}

	private Key getKey() {
		byte[] signKey = secret.getBytes();
		return Keys.hmacShaKeyFor(signKey);
	}

}
