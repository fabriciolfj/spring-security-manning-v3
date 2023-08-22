package com.github.autorizacaomethod.controller;

import com.github.autorizacaomethod.entity.Book;
import com.github.autorizacaomethod.entity.Employee;
import com.github.autorizacaomethod.service.BookService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/book")
public class BookController {

    @Autowired
    private BookService bookService;

    @GetMapping("/{name}")
    public Employee getDetails(@PathVariable("name") final String name) {
        return bookService.getBookDetails(name);
    }

    @GetMapping("/code/{code}")
    public Book get(@PathVariable Integer code) {
        return bookService.get(code);
    }
}
