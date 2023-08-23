package com.github.filtragemservice.service;

import com.github.filtragemservice.entity.Product;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ProductService {

    @PreFilter("filterObject.owner == authentication.name")
    public List<Product> execute(List<Product> products) {
        return products;
    }

    @PostFilter("filterObject.owner == authentication.name")
    public List<Product> findProducts() {
        var products = new ArrayList<Product>();

        products.add(new Product(1, "fabricio", "arroz"));
        products.add(new Product(2, "fabricio", "feijao"));
        products.add(new Product(3, "suzy", "farinha"));
        return products;
    }
}
