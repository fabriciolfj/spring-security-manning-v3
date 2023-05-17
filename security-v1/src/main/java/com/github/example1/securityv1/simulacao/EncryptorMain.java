package com.github.example1.securityv1.simulacao;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;

public class EncryptorMain {

    public static void main(String[] args) {
        final var generator = KeyGenerators.string();
        final var key = generator.generateKey();
        final var password = "secret";

        final var e = Encryptors.standard(password, key);
        final var result = e.encrypt("fabricio".getBytes());
        final var decrypt = e.decrypt(result);

        System.out.println(result);
        System.out.println(new String(decrypt));

        var by = new BCryptPasswordEncoder();
        System.out.println(by.encode("12345"));
    }
}
