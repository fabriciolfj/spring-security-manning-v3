package com.github.autorizacaomethod.entity;

public class Document {

    private String owner;

    public Document(final String owner) {
        this.owner = owner;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }
}
