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

    @Bean
    @Order(2)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        var authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        return http
                .securityMatcher(
                        authorizationServerConfigurer.getEndpointsMatcher()
                )
                .with(
                        authorizationServerConfigurer, (authorizationServer) -> {
                            authorizationServer.oidc(Customizer.withDefaults());
                        }
                )
                .authorizeHttpRequests(
                        (authorize) -> authorize.anyRequest().authenticated()
                )
                .exceptionHandling(
                        (exceptions) -> {
                            exceptions.authenticationEntryPoint(
                                    new LoginUrlAuthenticationEntryPoint("/login")
                            );
                        }
                )
                .oauth2ResourceServer(
                        (oauth2) -> oauth2.jwt(Customizer.withDefaults())
                )
                .build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(
                        (authorize) -> authorize.anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    @Order(4)
    public UserDetailsService userDetailsService() {
        var userDetails = User.builder()
                .username("user")
                .password(new BCryptPasswordEncoder().encode("password"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    @Order(5)
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grant -> grant.addAll(
                        Set.of(
                                AuthorizationGrantType.AUTHORIZATION_CODE,
                                AuthorizationGrantType.REFRESH_TOKEN,
                                AuthorizationGrantType.CLIENT_CREDENTIALS
                        )
                ))
                .redirectUris(redirect -> redirect.addAll(
                        Set.of(
                                "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc",
                                "http://127.0.0.1:8080/authorized"
                        )
                ))
                .scopes(scope -> scope.addAll(
                        Set.of(
                                OidcScopes.OPENID,
                                OidcScopes.PROFILE,
                                "message.read",
                                "message.write"
                        )
                ))
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    @Order(6)
    public JWKSource<SecurityContext> jwkSource() {
        var keyPair = generateRsaKey();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();

        var rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        var jwkSet = new JWKSet(rsaKey);

        return new ImmutableJWKSet<>(jwkSet);
    }

    private KeyPair generateRsaKey() {
        KeyPair keyPair;

        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        return keyPair;
    }


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
