package ma.fstt.authservice.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Réponse OAuth2 contenant les tokens
 */
public record TokenResponse(
        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("refresh_token")
        String refreshToken,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("expires_in")
        Long expiresIn
) {}