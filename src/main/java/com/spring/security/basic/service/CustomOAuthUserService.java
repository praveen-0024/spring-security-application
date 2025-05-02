package com.spring.security.basic.service;

import com.spring.security.basic.entity.Roles;
import com.spring.security.basic.entity.Users;
import com.spring.security.basic.repository.RolesRepository;
import com.spring.security.basic.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomOAuthUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UsersRepository usersRepository;
    private final RolesRepository roleRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();

        // Step 1: Fetch user info from provider
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // Step 2: Extract email or username based on provider
        String email = getEmailFromOAuth2User(registrationId, oAuth2User);

        // Step 3: Lookup user in DB
        Optional<Users> userOptional = usersRepository.findByUsername(email);
        Users user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
        } else {
            // Step 4: Register new user with default role
            user = new Users();
            user.setUsername(email);
            user.setEnabled(true);
            user.setPassword(""); // Not needed for OAuth

            Set<Roles> roles = new HashSet<>();
            roles.add(roleRepository.findByName("USER").orElseThrow(() -> new IllegalArgumentException("Role not found"))); // default role
            user.setRoles(roles);

            usersRepository.save(user);
        }

        // Step 5: Return a Spring Security compatible user
        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toList());

        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
        attributes.put("userId", user.getId());

        return new DefaultOAuth2User(authorities, attributes, "email");
    }

    private String getEmailFromOAuth2User(String registrationId, OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();

        if (registrationId.equals("google")) {
            return (String) attributes.get("email");
        } else if (registrationId.equals("github")) {
            return  attributes.get("login") + "@github.com"; // GitHub doesn't return email by default
        }

        throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
    }
}

