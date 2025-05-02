package com.spring.security.basic.service;

import com.spring.security.basic.dto.AuthResponse;
import com.spring.security.basic.dto.ChangePasswordRequest;
import com.spring.security.basic.dto.LoginRequest;
import com.spring.security.basic.dto.TokenRefreshRequest;
import com.spring.security.basic.entity.Roles;
import com.spring.security.basic.entity.Users;
import com.spring.security.basic.jwt.JwtService;
import com.spring.security.basic.repository.RolesRepository;
import com.spring.security.basic.repository.UsersRepository;
import com.spring.security.basic.users.UserDetailsImpl;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthenticationService {

    private final UsersRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EntityManager entityManager;

    public AuthenticationService(UsersRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager, EntityManager entityManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.entityManager = entityManager;
    }

    public void register(LoginRequest request) {
        // Check if user exists
        if (userRepository.findByUsername(request.userName()).isPresent()) {
            throw new RuntimeException("User already exists");
        }

        Set<Roles> rolesEntity = request.roleId().stream().map(id -> entityManager.getReference(Roles.class, id)).collect(Collectors.toSet());

        Users user = new Users();
        user.setUsername(request.userName());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setEnabled(true);
        user.setRoles(rolesEntity);

        userRepository.save(user);
    }

    public AuthResponse authenticate(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.userName(), request.password())
        );

        Users user = userRepository.findByUsername(request.userName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        return new AuthResponse(accessToken, refreshToken);
    }

    public AuthResponse refreshToken(TokenRefreshRequest request) {
        String refreshToken = request.refreshToken();
        String username = jwtService.extractUsername(refreshToken);

        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user.getRefreshToken() == null || !user.getRefreshToken().equals(refreshToken)) {
            throw new RuntimeException("Refresh token invalid or already revoked");
        }

        if (jwtService.isTokenExpired(refreshToken))
            throw new RuntimeException("Refresh token expired");

        String newAccessToken = jwtService.generateToken(user);
        return new AuthResponse(newAccessToken, refreshToken); // reuse same refresh token
    }

    public void logout(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Invalid Authorization header");
        }

        String jwt = authHeader.substring(7);
        String username = jwtService.extractUsername(jwt);

        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Invalidate the refresh token
        user.setRefreshToken(null);
        userRepository.save(user);
    }

    public void changePassword(ChangePasswordRequest request, Authentication authentication) {
        String username = authentication.getName();

        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Validate current password
        if (!passwordEncoder.matches(request.oldPassword(), user.getPassword())) {
            throw new RuntimeException("Current password is incorrect");
        }

        // Encode and update new password
        user.setPassword(passwordEncoder.encode(request.newPassword()));

        // Optional: Invalidate refresh token on password change
        user.setRefreshToken(null);

        userRepository.save(user);
    }
}

