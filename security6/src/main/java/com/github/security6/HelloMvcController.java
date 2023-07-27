package com.github.security6;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HelloMvcController {

    @GetMapping("/home")
    public String home() {
        return "home.html";
    }

    @GetMapping("/error")
    public String error() {
        return "error.html";
    }
}
