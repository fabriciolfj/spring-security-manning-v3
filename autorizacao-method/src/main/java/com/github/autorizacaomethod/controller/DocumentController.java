package com.github.autorizacaomethod.controller;

import com.github.autorizacaomethod.entity.Document;
import com.github.autorizacaomethod.service.DocumentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/documents")
public class DocumentController {

    @Autowired
    private DocumentService documentService;

    @GetMapping("/{code}")
    public Document getDetails(@PathVariable final String code) {
        return documentService.getDocument(code);
    }
}
