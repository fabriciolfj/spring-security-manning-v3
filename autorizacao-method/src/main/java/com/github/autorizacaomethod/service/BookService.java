package com.github.autorizacaomethod.service;

import com.github.autorizacaomethod.entity.Book;
import com.github.autorizacaomethod.entity.Employee;
import com.github.autorizacaomethod.repository.BookRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class BookService {

    @Autowired
    private BookRepository repository;

    @PostAuthorize("hasPermission(returnObject, 'ROLE_chefe')")
    public Book get(Integer code) {
        return repository.get(code);
    }

    private Map<String, Employee> records =
            Map.of("emma",
                    new Employee("Emma Thompson",
                            List.of("Karamazov Brothers"),
                            List.of("accountant", "reader")),
                    "natalie",
                    new Employee("Natalie Parker",
                            List.of("Beautiful Paris"),
                            List.of("researcher"))
            );
    @PostAuthorize("returnObject.roles.contains('reader')")
    public Employee getBookDetails(String name) {
        return records.get(name);
    }
}