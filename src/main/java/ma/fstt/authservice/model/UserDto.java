package ma.fstt.authservice.model;

import java.util.List;

/**
 * DTO représentant un utilisateur
 */
public record UserDto(
        Long id,
        String wallet,
        String username,
        List<String> roles,
        boolean enabled
) {}