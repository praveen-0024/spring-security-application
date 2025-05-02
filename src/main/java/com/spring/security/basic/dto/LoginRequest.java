package com.spring.security.basic.dto;

import java.util.List;

public record LoginRequest(String userName, String password, List<Long> roleId) {
}

