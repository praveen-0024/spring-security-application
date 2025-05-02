package com.spring.security.basic.repository;

import com.spring.security.basic.entity.OAuthClient;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

@Component
public class DatabaseClientRegistrationRepository implements ClientRegistrationRepository {

    private final OAuthClientRepository oauthClientRepo;

    public DatabaseClientRegistrationRepository(OAuthClientRepository oauthClientRepo) {
        this.oauthClientRepo = oauthClientRepo;
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        OAuthClient client = oauthClientRepo.findByRegistrationId(registrationId)
                .orElseThrow(() -> new IllegalArgumentException("OAuth client not found"));

        return ClientRegistration.withRegistrationId(client.getRegistrationId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .redirectUri(client.getRedirectUri())
                .authorizationUri(client.getAuthorizationUri())
                .tokenUri(client.getTokenUri())
                .userInfoUri(client.getUserInfoUri())
                .scope(client.getScope().split(","))
                .userNameAttributeName(client.getUserNameAttribute())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();
    }
}

