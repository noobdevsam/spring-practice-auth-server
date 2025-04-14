package com.example.springpracticeauthserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
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
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain actuatorSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher(EndpointRequest.toAnyEndpoint())
                .authorizeHttpRequests(
                        (authorize) -> authorize.anyRequest().permitAll()
                )
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
                        List.of(
                                AuthorizationGrantType.AUTHORIZATION_CODE,
                                AuthorizationGrantType.REFRESH_TOKEN,
                                AuthorizationGrantType.CLIENT_CREDENTIALS
                        )
                ))
                .redirectUris(redirect -> redirect.addAll(
                        List.of(
                                "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc",
                                "http://127.0.0.1:8080/authorized"
                        )
                ))
                .scopes(scope -> scope.addAll(
                        List.of(
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
                .issuer("http://localhost:9000")
                .build();
    }

}






















