package com.github.example1.securityv1.simulacao;

import org.springframework.security.crypto.keygen.KeyGenerators;

public class ChavesMain {

    public static void main(String[] args) {
        final var generator = KeyGenerators.string();
        final var key = generator.generateKey();

        System.out.println(key);
    }
}
