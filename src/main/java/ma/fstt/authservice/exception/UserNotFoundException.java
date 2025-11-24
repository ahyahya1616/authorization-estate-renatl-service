package ma.fstt.authservice.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Exception levée si l'utilisateur n'existe pas
 */
public class UserNotFoundException extends AuthenticationException {

    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}