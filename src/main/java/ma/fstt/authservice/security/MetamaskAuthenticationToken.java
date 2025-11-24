package ma.fstt.authservice.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Token d'authentification custom pour MetaMask
 */
public class MetamaskAuthenticationToken extends AbstractAuthenticationToken {

    private final String wallet;
    private final String signature;

    /**
     * Constructeur pour une authentification NON vérifiée
     */
    public MetamaskAuthenticationToken(String wallet, String signature) {
        super(null);
        this.wallet = wallet;
        this.signature = signature;
        setAuthenticated(false);
    }

    /**
     * Constructeur pour une authentification VÉRIFIÉE
     */
    public MetamaskAuthenticationToken(
            String wallet,
            String signature,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.wallet = wallet;
        this.signature = signature;
        setAuthenticated(true);
    }

    public String getWallet() {
        return wallet;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public Object getCredentials() {
        return signature;
    }

    @Override
    public Object getPrincipal() {
        return wallet;
    }
}