package com.github.autorizacaomethod.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableMethodSecurity
public class ProjectConfig {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private DocumentsPermissionEvaluator evaluator;
    @Autowired
    private BookPermissionEvaluator bookPermissionEvaluator;

    @Bean
    protected MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        var expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(evaluator);
        expressionHandler.setPermissionEvaluator(bookPermissionEvaluator);

        return expressionHandler;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var service = new InMemoryUserDetailsManager();

        var user1 = User.builder()
                .password(passwordEncoder.encode("1234"))
                .username("natalie")
                .authorities("read")
                .roles("admin", "chefe")
                .build();

        var user2 = User.builder()
                .password(passwordEncoder.encode("1234"))
                .username("emma")
                .authorities("write")
                .roles("manager")
                .build();

        service.createUser(user1);
        service.createUser(user2);
        return service;
    }
}
