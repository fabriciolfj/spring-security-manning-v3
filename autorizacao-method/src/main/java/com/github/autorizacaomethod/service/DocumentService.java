package com.github.autorizacaomethod.service;

import com.github.autorizacaomethod.entity.Document;
import com.github.autorizacaomethod.repository.DocumentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.stereotype.Service;

@Service
public class DocumentService {

    @Autowired
    private DocumentRepository documentRepository;

    @PostAuthorize("hasPermission(returnObject, 'ROLE_admin')")
    public Document getDocument(final String code) {
        return documentRepository.findDocument(code);
    }
}
