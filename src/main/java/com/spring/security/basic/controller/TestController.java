package com.spring.security.basic.controller;

import jakarta.servlet.ServletContext;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/user")
//    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> userEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("role: "+auth.getAuthorities());
        return ResponseEntity.ok("Hello USER!");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Hello ADMIN!");
    }

    @GetMapping("/common")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<String> commonEndpoint() {
        return ResponseEntity.ok("Hello Admin or User!");
    }
}

