package com.github.csrfservice;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Slf4j
@Controller
@RequestMapping("/product")
public class ProductController {

    @PostMapping("/add")
    public String add(@RequestParam final String name) {
        log.info("adding product {}", name);
        return "main.html";
    }
}
