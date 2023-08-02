package com.github.capitulo7;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@Configuration
public class ProjectConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        http.httpBasic(Customizer.withDefaults());

        String expression = """
                hasAuthority('read')  and
                !hasAuthority('delete')
                """;

        /*http.authorizeHttpRequests(
                c -> //c.requestMatchers("/hello").hasRole("ADMIN")
                       // .requestMatchers("/ciao").hasRole("MANAGER")
                       // .anyRequest().permitAll()//c.anyRequest()
                        //.hasAuthority("WRITE")
                        //.hasAnyAuthority("WRITE", "READ")
                        //.hasRole("ADMIN")
                        //.access(new WebExpressionAuthorizationManager(expression))
        );*/
        http.csrf(AbstractHttpConfigurer::disable);

        /*http.authorizeHttpRequests(c -> c.requestMatchers(HttpMethod.GET, "/a")
                .authenticated()
                .requestMatchers(HttpMethod.POST, "/a")
                .permitAll()
                .anyRequest()
                .denyAll()
        );*/
        http.authorizeHttpRequests(c -> c.requestMatchers("/product/{code:^[0-9]*$}")
                .permitAll()
                .anyRequest().denyAll());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var manager = new InMemoryUserDetailsManager();
        var user1 = User.withUsername("john")
                .password("12345")
                //.authorities("read")
                .roles("ADMIN", "TESTE")
                .build();

        var user2 = User.withUsername("jane")
                .password("12345")
                //.authorities("write", "read", "delete")
                .roles("MANAGER")
                .build();

        manager.createUser(user1);
        manager.createUser(user2);

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
