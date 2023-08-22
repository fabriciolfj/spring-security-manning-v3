package com.github.autorizacaomethod.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class NameService {

    private Map<String, List<String>> secrets = Map.of("natalie", List.of("Energico", "perfeito"), "emma", List.of("fantastico"));

    @PreAuthorize("hasAuthority('write')")
    public String getName() {
        return "fantastico";
    }

    @PreAuthorize("#name == authentication.principal.username")
    public List<String> getSecretNames(final String name) {
        return secrets.get(name);
    }
}
