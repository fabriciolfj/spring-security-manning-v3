package com.github.autorizacaomethod.controller;

import com.github.autorizacaomethod.service.NameService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class HelloController {

    @Autowired
    private NameService nameService;

    @GetMapping("/hello")
    public String getValue() {
        return "Hello " + nameService.getName();
    }

    @GetMapping("/hello/{name}")
    public List<String> getSecrets(@PathVariable("name") final String name) {
        return nameService.getSecretNames(name);
    }
}
