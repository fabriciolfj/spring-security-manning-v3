package com.github.autorizacaomethod.repository;

import com.github.autorizacaomethod.entity.Book;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class BookRepository {

    public Map<Integer, Book> values = Map.of(1, new Book("star wars", "emma"), 2, new Book("princisa nao sei", "natalie"));

    public Book get(Integer code) {
        return values.get(code);
    }
}
