package com.github.autorizacaomethod.entity;

public class Book {

    private String name;
    private String dono;

    public Book(String name, String dono) {
        this.name = name;
        this.dono = dono;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDono() {
        return dono;
    }

    public void setDono(String permission) {
        this.dono = permission;
    }
}
