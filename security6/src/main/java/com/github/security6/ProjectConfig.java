package com.github.security6;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;

@EnableAsync
@Configuration
@RequiredArgsConstructor
public class ProjectConfig {

    //private final AuthenticationProvider authenticationProvider;

    private final CustomAuthenticationFailureHandler authenticationFailureHandler;
    private final CustomAuthenticationSuccessHanlder authenticationSuccessHanlder;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*http.httpBasic(Customizer.withDefaults());
        http.authenticationProvider(authenticationProvider);
        http.authorizeHttpRequests(c -> c.anyRequest().authenticated());*/

        //http.httpBasic(Customizer.withDefaults());
        /*http.httpBasic(c -> {
            c.realmName("OTHER");
            c.authenticationEntryPoint(new CustomEntryPoint());
        });

        http.authorizeRequests().anyRequest().authenticated();*/

        http.formLogin(c ->
                c.successHandler(authenticationSuccessHanlder)
                        .failureHandler(authenticationFailureHandler)
        );

        http.authorizeHttpRequests(c -> c.anyRequest().authenticated());
        return http.build();
    }

    //@Bean
    public InitializingBean initializingBean() {
        return () -> SecurityContextHolder.setStrategyName(
                SecurityContextHolder.MODE_GLOBAL
        );
    }
}
