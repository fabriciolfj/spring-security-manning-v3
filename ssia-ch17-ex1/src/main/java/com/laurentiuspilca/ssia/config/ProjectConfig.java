package com.laurentiuspilca.ssia.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

import java.time.LocalTime;

@Configuration
@EnableReactiveMethodSecurity
public class ProjectConfig {

    /*@Bean
    public SecurityWebFilterChain securityWebFilterChain(final ServerHttpSecurity http) {
        http.httpBasic(Customizer.withDefaults());
        //http.authorizeExchange(e -> e.anyExchange().access(this::getAuthorizationDecisionMono));

        http.authorizeExchange(c -> c.pathMatchers(HttpMethod.GET, "/hello")
                .authenticated()
                .anyExchange()
                .permitAll()
        );

        return http.build();
    }*/

    /*
    private Mono<AuthorizationDecision>
    getAuthorizationDecisionMono(
            Mono<Authentication> a,
            AuthorizationContext c) {

        String path = getRequestPath(c);

        boolean restrictedTime =
                LocalTime.now().isAfter(LocalTime.NOON);

        if(path.equals("/hello")) {
            return  a.map(isAdmin())
                    .map(auth -> auth && !restrictedTime)
                    .map(AuthorizationDecision::new);
        }

        return Mono.just(new AuthorizationDecision(false));
    }

    private String getRequestPath(AuthorizationContext c) {
    return c.getExchange()
            .getRequest()
            .getPath()
            .toString();
  }

  private Function<Authentication, Boolean> isAdmin() {
    return p ->
      p.getAuthorities().stream()
       .anyMatch(e -> e.getAuthority().equals("ROLE_ADMIN"));
  }
    */

    @Bean
    public ReactiveUserDetailsService userDetailsService() {
        var  u1 = User.withUsername("john")
                .password("12345")
                .authorities("read")
                .roles("ADMIN")
                .build();

        var  u2 = User.withUsername("bill")
                .password("12345")
                .authorities("read")
                .roles("REGULAR_USEr")
                .build();

        var uds = new MapReactiveUserDetailsService(u1, u2);

        return uds;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
