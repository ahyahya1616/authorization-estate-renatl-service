package ma.fstt.authservice.security.oauth2;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

@Getter
@Setter

/**
 * Token d'authentification pour le grant type "metamask" dans Spring Authorization Server
 * Ce token représente une demande d'authentification OAuth2 avec le grant type custom "metamask"
 */
public class MetamaskGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    public static final AuthorizationGrantType METAMASK_GRANT_TYPE =
            new AuthorizationGrantType("metamask");

    private final String wallet;
    private final String signature;
    private final Set<String> scopes;


    /**
     * Constructeur pour créer un token d'authentification MetaMask
     *
     * @param wallet Adresse Ethereum du wallet MetaMask
     * @param signature Signature ECDSA générée par MetaMask
     * @param clientPrincipal Authentication du client OAuth2
     * @param scopes Scopes demandés
     * @param additionalParameters Paramètres additionnels de la requête
     */
    public MetamaskGrantAuthenticationToken(
            String wallet,
            String signature,
            Authentication clientPrincipal,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        super(METAMASK_GRANT_TYPE, clientPrincipal, additionalParameters);
        this.wallet = wallet;
        this.signature = signature;
        this.scopes = (scopes != null ? Collections.unmodifiableSet(scopes) : Collections.emptySet());

    }


}