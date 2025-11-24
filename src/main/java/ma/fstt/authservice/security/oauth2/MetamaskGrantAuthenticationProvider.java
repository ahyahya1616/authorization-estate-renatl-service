package ma.fstt.authservice.security.oauth2;

import ma.fstt.authservice.exception.InvalidSignatureException;
import ma.fstt.authservice.exception.UserNotFoundException;
import ma.fstt.authservice.model.UserDto;
import ma.fstt.authservice.service.SignatureVerificationService;
import ma.fstt.authservice.service.UserServiceClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.Principal;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Provider qui traite l'authentification MetaMask et génère les tokens OAuth2
 * via Spring Authorization Server
 *
 * Ce provider :
 * 1. Vérifie que le client OAuth2 supporte le grant type "metamask"
 * 2. Authentifie l'utilisateur via la signature MetaMask
 * 3. Génère l'Access Token et le Refresh Token
 * 4. Sauvegarde l'autorisation dans le AuthorizationService
 */
public class MetamaskGrantAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final SignatureVerificationService signatureVerificationService;
    private final UserServiceClient userServiceClient;

    public MetamaskGrantAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            SignatureVerificationService signatureVerificationService,
            UserServiceClient userServiceClient) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.signatureVerificationService = signatureVerificationService;
        this.userServiceClient = userServiceClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MetamaskGrantAuthenticationToken metamaskAuth =
                (MetamaskGrantAuthenticationToken) authentication;

        // 1. Récupérer et valider le client OAuth2
        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(metamaskAuth);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        // 2. Vérifier que le client supporte le grant type "metamask"
        if (!registeredClient.getAuthorizationGrantTypes()
                .contains(MetamaskGrantAuthenticationToken.METAMASK_GRANT_TYPE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // 3. Authentifier l'utilisateur via MetaMask
        String wallet = metamaskAuth.getWallet();
        String signature = metamaskAuth.getSignature();

        // Vérifier la signature ECDSA
        boolean isValid = signatureVerificationService.verifySignature(wallet, signature);
        if (!isValid) {
            throw new InvalidSignatureException("Signature MetaMask invalide");
        }

        // Récupérer l'utilisateur depuis UserManagementService
        UserDto user;
        try {
            user = userServiceClient.getUserByWallet(wallet);
        } catch (Exception e) {
            throw new UserNotFoundException("Utilisateur non trouvé pour le wallet : " + wallet);
        }

        // Créer les authorities (rôles)
        var authorities = user.roles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // Créer le principal authentifié
        Authentication principal = new UsernamePasswordAuthenticationToken(
                wallet,
                signature,
                authorities
        );

        // 4. Déterminer les scopes autorisés
        Set<String> authorizedScopes = registeredClient.getScopes();
        if (!metamaskAuth.getScopes().isEmpty()) {
            // Intersection entre les scopes demandés et ceux du client
            authorizedScopes = metamaskAuth.getScopes().stream()
                    .filter(registeredClient.getScopes()::contains)
                    .collect(Collectors.toSet());
        }

        // 5. Créer le contexte de génération de tokens
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizationGrantType(MetamaskGrantAuthenticationToken.METAMASK_GRANT_TYPE)
                .authorizedScopes(authorizedScopes);

        // 6. Générer Access Token
        OAuth2AccessToken accessToken = generateAccessToken(tokenContextBuilder);

        // 7. Générer Refresh Token (si le client le supporte)
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            refreshToken = generateRefreshToken(tokenContextBuilder);
        }

        // 8. Créer et sauvegarder l'autorisation OAuth2
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(wallet)
                .authorizationGrantType(MetamaskGrantAuthenticationToken.METAMASK_GRANT_TYPE)
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), principal);

        if (accessToken != null) {
            authorizationBuilder.accessToken(accessToken);
        }
        if (refreshToken != null) {
            authorizationBuilder.refreshToken(refreshToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        // 9. Retourner le token d'accès OAuth2
        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken
        );
    }

    /**
     * Génère l'Access Token
     */
    private OAuth2AccessToken generateAccessToken(
            DefaultOAuth2TokenContext.Builder builder) {
        DefaultOAuth2TokenContext tokenContext = builder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "Impossible de générer l'access token",
                    null
            );
            throw new OAuth2AuthenticationException(error);
        }

        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                tokenContext.getAuthorizedScopes()
        );
    }

    /**
     * Génère le Refresh Token
     */
    private OAuth2RefreshToken generateRefreshToken(
            DefaultOAuth2TokenContext.Builder builder) {
        DefaultOAuth2TokenContext tokenContext = builder
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build();

        OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);
        if (generatedRefreshToken == null) {
            return null;
        }

        return (OAuth2RefreshToken) generatedRefreshToken;
    }

    /**
     * Vérifie que le client est authentifié
     */
    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
            Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;

        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(
                authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MetamaskGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}