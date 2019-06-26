package io.github.jhipster.application.security.oauth2;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class AuthorizationHeaderUtil {

    private final OAuth2AuthorizedClientService clientService;

    public AuthorizationHeaderUtil(OAuth2AuthorizedClientService clientService) {
        this.clientService = clientService;
    }

    public Optional<String> getAuthorizationHeader() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String accessToken = null;
        AbstractAuthenticationToken authToken = (AbstractAuthenticationToken) authentication;
        if (authToken instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authToken;
            OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
                oauthToken.getAuthorizedClientRegistrationId(),
                oauthToken.getName());
            accessToken = client.getAccessToken().getTokenValue();
        } else if (authToken instanceof JwtAuthenticationToken) {
            accessToken = ((JwtAuthenticationToken) authToken).getToken().getTokenValue();
        }

        if (accessToken == null) {
            return Optional.empty();
        } else {
            String tokenType = "Bearer";
            String authorizationHeaderValue = String.format("%s %s", tokenType, accessToken);
            return Optional.of(authorizationHeaderValue);
        }
    }
}
