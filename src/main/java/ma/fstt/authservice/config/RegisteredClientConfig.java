package ma.fstt.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

/**
 * Configuration des clients OAuth2 enregistrés
 * ✅ Avec TokenSettings et ClientSettings correctement configurés
 */
@Configuration
public class RegisteredClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // ✅ Client Frontend avec authentification MetaMask
        RegisteredClient frontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("frontend-client")
                // Pas de secret pour un client public (SPA, Mobile App)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret("{noop}my-temp-secret")
                // ✅ Support du grant type custom "metamask"
                .authorizationGrantType(new AuthorizationGrantType("metamask"))
                // ✅ Support du refresh token
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // Scopes OpenID Connect standard
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                // Scopes personnalisés
                .scope("read")
                .scope("write")
                // ✅ Configuration des tokens
                .tokenSettings(TokenSettings.builder()
                        // Access token valide 15 minutes
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        // Refresh token valide 7 jours
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        // ✅ Ne pas réutiliser les refresh tokens (sécurité)
                        .reuseRefreshTokens(false)
                        .build())
                // ✅ Configuration du client
                .clientSettings(ClientSettings.builder()
                        // Pas de consentement requis (authentification directe)
                        .requireAuthorizationConsent(false)
                        // Pas de PKCE requis pour ce client
                        .requireProofKey(false)
                        .build())
                .build();

        // ✅ Client pour les services internes (machine-to-machine)
        RegisteredClient serviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("service-client")
                // {noop} = pas de BCrypt en dev, utiliser {bcrypt} en production
                .clientSecret("{noop}service-secret-2024")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // Grant type pour communication service-to-service
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                // Scopes spécifiques aux services
                .scope("service.read")
                .scope("service.write")
                .scope("service.admin")
                // Configuration des tokens pour les services
                .tokenSettings(TokenSettings.builder()
                        // Access token valide 30 minutes pour les services
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        // Pas de refresh token pour client_credentials
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(frontendClient, serviceClient);
    }
}