package com.github.autorizacaomethod.config;

import com.github.autorizacaomethod.entity.Book;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component
public class BookPermissionEvaluator implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        var book = (Book) targetDomainObject;
        var role = (String) permission;

        boolean chefe = authentication
                .getAuthorities()
                .stream()
                .anyMatch(p -> p.getAuthority().equals(role));


        return chefe || book.getDono().equals(authentication.getName());
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
