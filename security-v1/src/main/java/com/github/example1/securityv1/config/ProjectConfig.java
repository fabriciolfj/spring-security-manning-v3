package com.github.example1.securityv1.config;

import com.github.example1.securityv1.service.InMemoryUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.util.List;

@Configuration
public class ProjectConfig {

    /*@Bean
    UserDetailsService userDetailsService() {
        var user = User.withUsername("fabricio")
                .password("1234")
                .authorities("read")
                .build();
        var user2 = User.withUsername("teste")
                .password("1234")
                .authorities("read")
                .build();

        return new InMemoryUserDetailService(List.of(user, user2));
    }*/

    @Bean
    public UserDetailsService userDetailsService(final DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    //@Autowired
    //public CustomAuthenticationProvider authenticationProvider;

    @Bean
    SecurityFilterChain configure(final HttpSecurity http) throws Exception {
        http.httpBasic();
        //http.authenticationProvider(authenticationProvider);

        http.authorizeHttpRequests()
                .anyRequest()
                //.permitAll();
                .authenticated();

        return http.build();
    }
}
