package com.github.csrfservice;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String getHello(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        log.info("CSRF token: "  + token.getToken());
        return "hello";
    }

    @PostMapping("/hello")
    public String postHello() {
        return "hello post";
    }
}
