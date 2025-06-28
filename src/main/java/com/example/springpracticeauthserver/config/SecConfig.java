package com.example.springpracticeauthserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecConfig {

    @Value("${jwt.issuer-uri}")
    String issuer;

    /**
     * Configures a security filter chain for actuator endpoints.
     * <p>
     * This filter chain matches requests to any actuator endpoint and permits all requests
     * without requiring authentication. It is applied with the highest order (1) to ensure
     * that actuator endpoints are accessible regardless of other security configurations.
     *
     * @param http the {@link HttpSecurity} object used to configure the security filter chain
     * @return the configured {@link SecurityFilterChain} for actuator endpoints
     * @throws Exception if an error occurs while configuring the security filter chain
     */
    @Bean
    @Order(1)
    public SecurityFilterChain actuatorSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Matches requests to any actuator endpoint
                .securityMatcher(EndpointRequest.toAnyEndpoint())
                // Permits all requests to actuator endpoints
                .authorizeHttpRequests(
                        (authorize) -> authorize.anyRequest().permitAll()
                )
                // Builds the security filter chain
                .build();
    }

    /**
     * Configures a security filter chain for the authorization server.
     * <p>
     * This filter chain matches requests to the authorization server endpoints and ensures
     * that all requests are authenticated. It also configures OpenID Connect (OIDC) support,
     * exception handling for unauthenticated requests, and JWT-based resource server support.
     *
     * @param http the {@link HttpSecurity} object used to configure the security filter chain
     * @return the configured {@link SecurityFilterChain} for the authorization server
     * @throws Exception if an error occurs while configuring the security filter chain
     */
    @Bean
    @Order(2)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // Configures the authorization server
        var authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        return http
                // Matches requests to authorization server endpoints
                .securityMatcher(
                        authorizationServerConfigurer.getEndpointsMatcher()
                )
                // Applies the authorization server configuration
                .with(
                        authorizationServerConfigurer, (authorizationServer) -> {
                            // Enables OpenID Connect (OIDC) support
                            authorizationServer.oidc(Customizer.withDefaults());
                        }
                )
                // Requires authentication for all requests
                .authorizeHttpRequests(
                        (authorize) -> authorize.anyRequest().authenticated()
                )
                // Configures exception handling for unauthenticated requests
                .exceptionHandling(
                        (exceptions) -> {
                            exceptions.authenticationEntryPoint(
                                    new LoginUrlAuthenticationEntryPoint("/login")
                            );
                        }
                )
                // Configures JWT-based resource server support
                .oauth2ResourceServer(
                        (oauth2) -> oauth2.jwt(Customizer.withDefaults())
                )
                // Builds the security filter chain
                .build();
    }

    /**
     * Configures the default security filter chain for the application.
     * <p>
     * This filter chain ensures that all requests are authenticated and enables form-based login.
     * It is applied with the order (3), meaning it is used after higher-priority filter chains.
     *
     * @param http the {@link HttpSecurity} object used to configure the security filter chain
     * @return the configured {@link SecurityFilterChain} for the default security settings
     * @throws Exception if an error occurs while configuring the security filter chain
     */
    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Requires authentication for all requests
                .authorizeHttpRequests(
                        (authorize) -> authorize.anyRequest().authenticated()
                )
                // Enables form-based login
                .formLogin(Customizer.withDefaults())
                // Builds the security filter chain
                .build();
    }

    /**
     * Configures a user details service with an in-memory user.
     * <p>
     * This method creates a single user with the username "user", a password encoded using
     * {@link BCryptPasswordEncoder}, and the role "USER". The user is stored in an
     * {@link InMemoryUserDetailsManager}, which is returned as the user details service.
     *
     * @return the configured {@link UserDetailsService} with an in-memory user
     */
    @Bean
    @Order(4)
    public UserDetailsService userDetailsService() {
        var userDetails = User.builder()
                // Sets the username for the user
                .username("user")
                // Encodes the password using BCryptPasswordEncoder
                .password(new BCryptPasswordEncoder().encode("password"))
                // Assigns the role "USER" to the user
                .roles("USER")
                .build();

        // Returns an in-memory user details manager containing the user
        return new InMemoryUserDetailsManager(userDetails);
    }

    /**
     * Configures a repository for managing registered OAuth2 clients.
     * <p>
     * This method creates an in-memory repository containing a single registered client
     * with the following properties:
     * <ul>
     *   <li>Client ID: "messaging-client"</li>
     *   <li>Client Secret: "{noop}secret" (no encoding applied)</li>
     *   <li>Authentication Method: CLIENT_SECRET_BASIC</li>
     *   <li>Authorization Grant Types: Authorization Code, Refresh Token, Client Credentials</li>
     *   <li>Redirect URIs: "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc" and "http://127.0.0.1:8080/authorized"</li>
     *   <li>Scopes: OpenID, Profile, message.read, message.write</li>
     *   <li>Client Settings: Requires authorization consent</li>
     * </ul>
     * The registered client is stored in an {@link InMemoryRegisteredClientRepository}, which is returned.
     *
     * @return the configured {@link RegisteredClientRepository} containing the registered client
     */
    @Bean
    @Order(5)
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // Sets the client ID for the registered client
                .clientId("messaging-client")
                // Sets the client secret without encoding
                .clientSecret("{noop}secret")
                // Configures the client authentication method
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // Configures the supported authorization grant types
                .authorizationGrantTypes(grant -> grant.addAll(
                        Set.of(
                                AuthorizationGrantType.AUTHORIZATION_CODE,
                                AuthorizationGrantType.REFRESH_TOKEN,
                                AuthorizationGrantType.CLIENT_CREDENTIALS
                        )
                ))
                // Configures the redirect URIs for the client
                .redirectUris(redirect -> redirect.addAll(
                        Set.of(
                                "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc",
                                "http://127.0.0.1:8080/authorized"
                        )
                ))
                // Configures the scopes for the client
                .scopes(scope -> scope.addAll(
                        Set.of(
                                OidcScopes.OPENID,
                                OidcScopes.PROFILE,
                                "message.read",
                                "message.write"
                        )
                ))
                // Configures client settings to require authorization consent
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        // Returns an in-memory repository containing the registered client
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * Configures a JWK (JSON Web Key) source for JWT decoding.
     * <p>
     * This method generates an RSA key pair and creates a JWK set containing the RSA key.
     * The JWK set is wrapped in an {@link ImmutableJWKSet}, which provides a read-only view
     * of the JWK set. The JWK source is used for providing the public key required for
     * verifying JWTs.
     *
     * @return the configured {@link JWKSource} for JWT decoding
     */
    @Bean
    @Order(6)
    public JWKSource<SecurityContext> jwkSource() {
        // Generates an RSA key pair
        var keyPair = generateRsaKey();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // Creates an RSA key with the public and private keys
        var rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        // Creates a JWK set containing the RSA key
        var jwkSet = new JWKSet(rsaKey);

        // Returns an immutable JWK source containing the JWK set
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Generates an RSA key pair for cryptographic operations.
     * <p>
     * This method uses the {@link KeyPairGenerator} to create a new RSA key pair with a key size of 2048 bits.
     * If an error occurs during key pair generation, an {@link IllegalStateException} is thrown.
     *
     * @return the generated {@link KeyPair} containing the RSA public and private keys
     */
    private KeyPair generateRsaKey() {
        KeyPair keyPair;

        try {
            // Creates a KeyPairGenerator instance for RSA algorithm
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            // Initializes the generator with a key size of 2048 bits
            keyPairGenerator.initialize(2048);
            // Generates the RSA key pair
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            // Throws an IllegalStateException if key pair generation fails
            throw new IllegalStateException(e);
        }

        return keyPair;
    }


    /**
     * Configures a JWT decoder for the authorization server.
     * <p>
     * This method creates a {@link JwtDecoder} bean using the provided {@link JWKSource}.
     * The JWK source supplies the public key required for verifying JWTs issued by the authorization server.
     *
     * @param jwkSource the {@link JWKSource} used to provide the public key for JWT verification
     * @return the configured {@link JwtDecoder} for decoding JWTs
     */
    @Bean
    @Order(7)
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    @Order(8)
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }

}

// This configuration class sets up the security filter chains for the application.
// It defines three filter chains: one for actuator endpoints, one for the authorization server,
// and one for the default security filter chain.
// The actuator filter chain allows all requests to actuator endpoints.
// The authorization server filter chain configures the OAuth2 authorization server,
// including OIDC support and resource server support.
// The default security filter chain requires authentication for all requests and enables form login.
// The class also defines a user details service with a single user, a registered client repository
// with a client, and a JWK source for JWT decoding.
// The RSA key pair is generated for signing JWTs.
// The authorization server settings specify the issuer URL for the authorization server.
// The class is annotated with @Configuration and @EnableWebSecurity to indicate that it is a configuration class for security.
// The @Order annotations specify the order in which the filter chains are applied.
// The actuator filter chain has the highest order (1), followed by the authorization server filter chain (2),
// and the default security filter chain (3).
// The user details service (4), JWK source (5), JWT decoder (6), and authorization server settings (7)
// are also defined as beans with their respective orders.
// The registered client repository (8) is defined with a single registered client that supports
// multiple authorization grant types and redirect URIs.
// The client settings require authorization consent for the registered client.
// The JWK source is used to provide the public key for JWT verification.
// The RSA key pair is generated using a KeyPairGenerator.
// The generateRsaKey() method generates a new RSA key pair with a key size of 2048 bits.
// The public key is used to create an RSAKey object, which is then used to create a JWKSet.
// The JWKSet is wrapped in an ImmutableJWKSet to provide a read-only view of the JWK set.
// The JWK source is then used to create a JwtDecoder bean for decoding JWTs.
// The authorization server settings specify the issuer URL for the authorization server.
// The issuer URL is used in the JWT token to identify the authorization server.
// The authorization server settings are defined as a bean with the @Bean annotation.
// The authorizationServerSettings() method creates an instance of AuthorizationServerSettings
// with the specified issuer URL and returns it.
