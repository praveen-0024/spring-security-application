package com.spring.security.basic.dto;

public record AuthResponse(String token, String refreshToken) {
}
