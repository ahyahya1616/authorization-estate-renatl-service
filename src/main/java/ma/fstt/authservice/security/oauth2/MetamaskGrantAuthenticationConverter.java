package ma.fstt.authservice.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Convertit une requête HTTP POST /oauth2/token avec grant_type=metamask
 * en MetamaskGrantAuthenticationToken
 *
 * Cette classe est responsable de :
 * 1. Vérifier que le grant_type est "metamask"
 * 2. Extraire les paramètres wallet et signature
 * 3. Créer le token d'authentification approprié
 */
public class MetamaskGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        // Vérifier que c'est bien grant_type=metamask
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!"metamask".equals(grantType)) {
            return null; // Pas notre grant type, laisser d'autres converters gérer
        }

        // Récupérer le client principal (authentifié via Basic Auth, client_secret, etc.)
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // Extraire les paramètres custom MetaMask
        String wallet = request.getParameter("wallet");
        String signature = request.getParameter("signature");

        // Validation des paramètres requis
        if (!StringUtils.hasText(wallet)) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "Le paramètre 'wallet' est requis pour grant_type=metamask"
            );
        }

        if (!StringUtils.hasText(signature)) {
            throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "Le paramètre 'signature' est requis pour grant_type=metamask"
            );
        }

        // Extraire les scopes demandés
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        Set<String> requestedScopes = new HashSet<>();
        if (StringUtils.hasText(scope)) {
            for (String s : scope.split(" ")) {
                if (StringUtils.hasText(s)) {
                    requestedScopes.add(s);
                }
            }
        }

        // Extraire tous les paramètres additionnels
        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.SCOPE) &&
                    !key.equals("wallet") &&
                    !key.equals("signature")) {
                additionalParameters.put(key, (value.length == 1) ? value[0] : value);
            }
        });

        // Créer le token d'authentification MetaMask
        return new MetamaskGrantAuthenticationToken(
                wallet,
                signature,
                clientPrincipal,
                requestedScopes,
                additionalParameters
        );
    }

    private void throwError(String errorCode, String description) {
        OAuth2Error error = new OAuth2Error(errorCode, description, null);
        throw new OAuth2AuthenticationException(error);
    }
}