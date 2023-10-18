package com.github.servidorrecursos;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectConfig {

    @Value("${keySetURI}")
    private String keySetUri;

    @Value("${introspectionUri}")
    private String introspectionUri;

    @Value("${resourceserver.clientID}")
    private String resourceServerClientID;

    @Value("${resourceserver.secret}")
    private String resourceServerSecret;

    @Autowired
    private JwtAuthenticationConverter converter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*http.oauth2ResourceServer(
                c -> c.opaqueToken(
                        o -> o.introspectionUri(introspectionUri)
                                .introspectionClientCredentials(
                                        resourceServerClientID,
                                        resourceServerSecret)
                )
        );*/

        http.oauth2ResourceServer(c -> c.jwt(
                j -> j.jwkSetUri(keySetUri)
                        .jwtAuthenticationConverter(converter)
        ));

        http.authorizeHttpRequests(c -> c.anyRequest().authenticated());
        return http.build();
    }
}