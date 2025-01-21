package authentication.server.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import authentication.server.auth.services.CustomOidcUserService;
import jakarta.servlet.http.HttpServletResponse;


@EnableWebSecurity
@Configuration
public class AuthorizationServerConfig {

    private final CustomOidcUserService customOidcUserService;

    public AuthorizationServerConfig(CustomOidcUserService customOidcUserService) {
        this.customOidcUserService = customOidcUserService;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(oidc -> oidc
                .clientRegistrationEndpoint(clientReg ->
                    clientReg.clientRegistrationResponseHandler((request, response, authentication) -> {
                        response.setStatus(HttpServletResponse.SC_OK);
                    })
                )
            );

        http.oauth2ResourceServer(resourceServer -> resourceServer.jwt());

        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz
            .requestMatchers("/login", "/oauth2/authorization/*").permitAll()
            .anyRequest().authenticated()
        );
        http.oauth2Login(oauth2 -> oauth2
            .userInfoEndpoint(userInfo -> userInfo.oidcUserService(customOidcUserService))
            .defaultSuccessUrl("/home", true)
        );
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId("google-client-id")
            .clientId("831065904177-pfo1o5skuamubqvgr8ft7s3gua7je0fk.apps.googleusercontent.com")
            .clientSecret("{noop}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")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:9000/login/oauth2/code/google")
            .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }


    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
    }
}
