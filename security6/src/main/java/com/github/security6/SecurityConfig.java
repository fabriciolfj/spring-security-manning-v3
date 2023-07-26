package com.github.security6;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        var user = User.withUsername("fabricio")
                .password(passwordEncoder.encode("1234"))
                .authorities("read")
                .build();
        var user2 = User.withUsername("teste")
                .password(passwordEncoder.encode("1234"))
                .authorities("read")
                .build();

        return new InMemoryUserDetailService(List.of(user, user2));
    }
}
