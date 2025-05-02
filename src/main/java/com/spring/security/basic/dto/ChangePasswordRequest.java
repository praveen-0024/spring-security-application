package com.spring.security.basic.dto;

public record ChangePasswordRequest(String newPassword, String oldPassword) {
}
