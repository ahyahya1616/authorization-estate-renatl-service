package ma.fstt.authservice.config;

import ma.fstt.authservice.security.MetamaskAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuration Spring Security globale
 * ✅ ORDER 2 = S'applique après le Authorization Server Filter Chain
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final MetamaskAuthenticationProvider metamaskAuthenticationProvider;

    public SecurityConfig(MetamaskAuthenticationProvider metamaskAuthenticationProvider) {
        this.metamaskAuthenticationProvider = metamaskAuthenticationProvider;
    }

    /**
     * Security Filter Chain pour les endpoints REST publics et l'API
     * ORDER 2 = Priorité après le Authorization Server
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        // ✅ Endpoints publics MetaMask
                        .requestMatchers("/metamask/nonce").permitAll()

                        // ✅ Endpoints OAuth2 publics (JWKS, discovery)
                        .requestMatchers("/oauth2/jwks").permitAll()
                        .requestMatchers("/.well-known/**").permitAll()

                        // ✅ Health check et actuator
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/actuator/info").permitAll()

                        // ✅ Logout nécessite une authentification
                        .requestMatchers("/metamask/logout/**").authenticated()

                        // ✅ Tout le reste nécessite une authentification
                        .anyRequest().authenticated()
                )

                // ✅ Sessions stateless pour une API REST
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // ✅ Désactiver form login (on utilise MetaMask)
                .formLogin(form -> form.disable())

                // ✅ HTTP Basic pour les clients OAuth2 (service-client)
                .httpBasic(Customizer.withDefaults())

                // ✅ Désactiver CSRF (API REST avec tokens)
                .csrf(csrf -> csrf.disable())

                // ✅ CORS géré par CorsConfig
                .cors(Customizer.withDefaults());

        return http.build();
    }

    /**
     * AuthenticationManager avec le provider custom MetaMask
     * ✅ Ce provider est utilisé pour l'authentification manuelle si nécessaire
     * (Le OAuth2 grant type provider est enregistré séparément)
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(metamaskAuthenticationProvider);
    }
}