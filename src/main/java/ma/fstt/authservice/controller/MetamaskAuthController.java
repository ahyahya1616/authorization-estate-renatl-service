package ma.fstt.authservice.controller;

import ma.fstt.authservice.model.NonceResponse;
import ma.fstt.authservice.service.NonceService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.bind.annotation.*;

/**
 * Controller simplifié pour l'authentification MetaMask
 *
 * ✅ La génération de tokens est maintenant gérée par Spring Authorization Server
 * via l'endpoint standard /oauth2/token avec grant_type=metamask
 */
@RestController
@RequestMapping("/metamask")
public class MetamaskAuthController {

    private final NonceService nonceService;
    private final OAuth2AuthorizationService authorizationService;

    public MetamaskAuthController(
            NonceService nonceService,
            OAuth2AuthorizationService authorizationService) {
        this.nonceService = nonceService;
        this.authorizationService = authorizationService;
    }

    /**
     * Endpoint 1: Obtenir un nonce pour la signature MetaMask
     *
     * GET /metamask/nonce?wallet=0x123...
     *
     * @param wallet Adresse Ethereum du wallet
     * @return Nonce à signer
     */
    @GetMapping("/nonce")
    public ResponseEntity<NonceResponse> getNonce(@RequestParam String wallet) {
        String nonce = nonceService.generateAndStoreNonce(wallet);
        return ResponseEntity.ok(new NonceResponse(nonce));
    }

    /**
     * ✅ L'authentification se fait maintenant via l'endpoint standard OAuth2:
     *
     * POST /oauth2/token
     * Content-Type: application/x-www-form-urlencoded
     *
     * grant_type=metamask
     * &wallet=0x123...
     * &signature=0xabc...
     * &scope=openid profile read write
     *
     * Réponse:
     * {
     *   "access_token": "eyJhbGc...",
     *   "refresh_token": "eyJhbGc...",
     *   "token_type": "Bearer",
     *   "expires_in": 900,
     *   "scope": "openid profile read write"
     * }
     */

    /**
     * ✅ Le refresh token se fait aussi via l'endpoint standard:
     *
     * POST /oauth2/token
     * Content-Type: application/x-www-form-urlencoded
     *
     * grant_type=refresh_token
     * &refresh_token=eyJhbGc...
     * &client_id=frontend-client
     */

    /**
     * Endpoint pour déconnecter un utilisateur (invalider les tokens)
     *
     * POST /metamask/logout
     * Authorization: Bearer <access_token>
     *
     * @param authHeader Header Authorization contenant le token
     * @return 200 OK si le logout réussit
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader) {
        // Extraire le token du header
        String token = authHeader.replace("Bearer ", "");

        // Trouver l'autorisation associée au token
        OAuth2Authorization authorization = authorizationService.findByToken(
                token,
                OAuth2TokenType.ACCESS_TOKEN
        );

        // Supprimer l'autorisation (invalide access_token et refresh_token)
        if (authorization != null) {
            authorizationService.remove(authorization);
        }

        return ResponseEntity.ok().build();
    }

    /**
     * ✅ Endpoint optionnel: Déconnecter par wallet address
     * Utile si le frontend a perdu le token mais connaît le wallet
     *
     * DELETE /metamask/logout/wallet/{wallet}
     *
     * @param wallet Adresse Ethereum
     * @return 200 OK
     */
    @DeleteMapping("/logout/wallet/{wallet}")
    public ResponseEntity<Void> logoutByWallet(@PathVariable String wallet) {
        // Rechercher toutes les autorisations pour ce wallet
        // Note: InMemoryOAuth2AuthorizationService ne supporte pas la recherche par principal
        // En production, utiliser une DB et une requête custom

        // Pour le moment, retourner OK
        // TODO: Implémenter avec un AuthorizationService basé sur une DB
        return ResponseEntity.ok().build();
    }
}